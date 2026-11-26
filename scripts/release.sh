#!/usr/bin/env bash
# Makes a release of Kubedog on this Mac: builds for macOS (Apple silicon), Linux (amd64, arm64) and Windows
# (amd64, arm64), packs them, and after a question uploads them to GitHub and updates the Homebrew formula.
#
#   scripts/release.sh                         build, show what was made, ask, upload
#   scripts/release.sh --build-only            build and pack only; nothing leaves this computer
#   scripts/release.sh --build-only --notarize the same, and the Mac app goes to Apple for its check (nothing is published)
#
# The Mac program is signed with the "Developer ID Application" certificate in the keychain and checked by Apple
# (notarized), so it opens without a warning, also on a Mac without internet. Apple's check is asked for after the
# question, as it sends the app to Apple. Needed once for that:
#   the certificate, from developer.apple.com (Certificates > Developer ID Application), in the login keychain
#   xcrun notarytool store-credentials kubedog-notary --apple-id <Apple ID> --team-id <team>
#
# The version is the one in Cargo.toml. Source and downloads are in the same place on GitHub ($GH_REPO, the
# remote "origin"): the release is a tag on main with the packed programs attached.
#
# Needed once: rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-pc-windows-gnu \
#                aarch64-pc-windows-gnullvm
#              brew install zig mingw-w64 makensis gh
#              cargo install cargo-zigbuild && cargo install cargo-about --features cli
set -euo pipefail

GH_REPO="${KUBEDOG_GH_REPO:-pezzking/kubedog}"      # the source and the downloads
TAP_REPO="${KUBEDOG_TAP_REPO:-pezzking/homebrew-tap}" # brew install pezzking/tap/kubedog
GLIBC=2.28                                            # the oldest Linux the builds run on
KUBECTL_VERSION="${KUBEDOG_KUBECTL_VERSION:-v1.37.2}"  # the kubectl inside the Windows installers; raise it with a release

BUNDLE_ID="io.github.pezzking.kubedog"
NOTARY="${KUBEDOG_NOTARY_PROFILE:-kubedog-notary}"     # the name the login for Apple's check is kept under

BUILD_ONLY=0
NOTARIZE=0
for a in "$@"; do
    case "$a" in
        --build-only) BUILD_ONLY=1 ;;
        --notarize) NOTARIZE=1 ;;
        *) echo "unknown option: $a" >&2; exit 1 ;;
    esac
done
[ "$BUILD_ONLY" = 1 ] || NOTARIZE=0   # a release asks Apple after its question

cd "$(dirname "$0")/.."
ROOT="$PWD"
export PATH="$HOME/.cargo/bin:$PATH"
say() { printf '\n== %s\n' "$*"; }
stop() { printf '\nStopped: %s\n' "$*" >&2; exit 1; }

V="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[ -n "$V" ] || stop "no version found in Cargo.toml"
TAG="v$V"
DIST="$ROOT/target/dist"

for tool in cargo cargo-zigbuild cargo-about zig x86_64-w64-mingw32-gcc makensis gh shasum zip codesign hdiutil ditto xcrun; do
    command -v "$tool" >/dev/null || stop "$tool isn't installed (see the top of this script)"
done
# The certificate is found by its kind, so no name is written here.
SIGN_ID="${KUBEDOG_SIGN_ID:-$(security find-identity -v -p codesigning | sed -n 's/^ *[0-9]*) \([0-9A-F]*\) "Developer ID Application: .*/\1/p' | head -1)}"
[ -n "$SIGN_ID" ] || stop "no 'Developer ID Application' certificate in the keychain (see the top of this script)"
if [ "$BUILD_ONLY" = 0 ] || [ "$NOTARIZE" = 1 ]; then
    xcrun notarytool history --keychain-profile "$NOTARY" >/dev/null 2>&1 \
        || stop "the login for Apple's check ($NOTARY) isn't in the keychain or isn't accepted (see the top of this script)"
fi

say "Kubedog $V: checks"
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || stop "not on main"
if [ -n "$(git status --porcelain)" ]; then
    [ "$BUILD_ONLY" = 1 ] || stop "there are changes that aren't committed"
    echo "Note: there are changes that aren't committed (fine for --build-only)."
fi
if [ "$BUILD_ONLY" = 0 ]; then
    git fetch -q origin
    [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || stop "main here and on the server differ; push or pull first"
    git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && stop "the tag $TAG exists already; raise the version in Cargo.toml"
    gh release view "$TAG" --repo "$GH_REPO" >/dev/null 2>&1 && stop "$GH_REPO has a release $TAG already"
fi
cargo test --quiet 2>&1 | grep -E "^test result|FAILED|panicked" || true
cargo test --quiet >/dev/null 2>&1 || stop "the tests fail"

# Paths of this computer (the home folder, the user's name) must not end up inside the programs.
export RUSTFLAGS="--remap-path-prefix=$ROOT=kubedog --remap-path-prefix=$HOME/.cargo=cargo --remap-path-prefix=$HOME/.rustup=rustup"

say "Build: macOS, Apple silicon"
cargo build --release --locked --target aarch64-apple-darwin
say "Build: Linux, amd64"
cargo zigbuild --release --locked --target "x86_64-unknown-linux-gnu.$GLIBC"
say "Build: Linux, arm64"
cargo zigbuild --release --locked --target "aarch64-unknown-linux-gnu.$GLIBC"
say "Build: Windows, amd64"
cargo build --release --locked --target x86_64-pc-windows-gnu
say "Build: Windows, arm64"
cargo zigbuild --release --locked --target aarch64-pc-windows-gnullvm

say "Notices of the libraries"
rm -rf "$DIST"; mkdir -p "$DIST" "$ROOT/target/notices"
NOTICES="$ROOT/target/notices/THIRD-PARTY-LIBRARIES.txt"
cargo about generate -c scripts/about.toml scripts/about.hbs -o "$NOTICES"

say "Pack"
pack() { # pack <name> <built program> <tar|zip>
    local name="kubedog-$V-$1" dir="$DIST/kubedog-$V-$1"
    mkdir -p "$dir/licenses"
    cp "$2" "$dir/"
    cp LICENSE THIRD-PARTY.md "$NOTICES" "$dir/"
    cp assets/fonts/*-OFL.txt "$dir/licenses/"
    if [ "$3" = zip ]; then
        (cd "$DIST" && zip -qr "$name.zip" "$name")
    else
        (cd "$DIST" && COPYFILE_DISABLE=1 tar --no-xattrs -czf "$name.tar.gz" "$name")
    fi
    rm -rf "$dir"
}

# Asks Apple to check what's in a .zip or .dmg, and waits for the answer.
apple_checks() {
    local out
    out="$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY" --wait 2>&1)" || { echo "$out"; stop "Apple's check of $(basename "$1") couldn't be asked for"; }
    echo "$out" | grep -q "status: Accepted" || { echo "$out"; stop "Apple didn't accept $(basename "$1"); see: xcrun notarytool log <id> --keychain-profile $NOTARY"; }
}

# The two Mac downloads: the program alone (.tar.gz, for Homebrew) and Kubedog.app in a disk image (.dmg).
mac_pack() { # mac_pack <time from Apple: none|apple> <ask Apple to check: 0|1>
    local stamp="--timestamp=none" m="$ROOT/target/mac-pack" dmg="$DIST/kubedog-$V-macos-arm64.dmg"
    [ "$1" = apple ] && stamp="--timestamp"
    rm -rf "$m" "$dmg" "$DIST/kubedog-$V-macos-arm64.tar.gz"
    local app="$m/dmg/Kubedog.app"
    mkdir -p "$m/alone" "$app/Contents/MacOS" "$app/Contents/Resources/licenses"

    cp target/aarch64-apple-darwin/release/kubedog "$m/alone/kubedog"
    codesign --force "$stamp" --options runtime -i "$BUNDLE_ID" -s "$SIGN_ID" "$m/alone/kubedog"

    cp target/aarch64-apple-darwin/release/kubedog "$app/Contents/MacOS/kubedog"
    cp assets/icons/kubedog-macos.icns "$app/Contents/Resources/kubedog.icns"
    cp LICENSE THIRD-PARTY.md "$NOTICES" "$app/Contents/Resources/"
    cp assets/fonts/*-OFL.txt "$app/Contents/Resources/licenses/"
    cat > "$app/Contents/Info.plist" <<PLIST_END
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Kubedog</string>
    <key>CFBundleDisplayName</key><string>Kubedog</string>
    <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
    <key>CFBundleExecutable</key><string>kubedog</string>
    <key>CFBundleIconFile</key><string>kubedog</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$V</string>
    <key>CFBundleVersion</key><string>$V</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST_END
    codesign --force "$stamp" --options runtime -s "$SIGN_ID" "$app"
    codesign --verify --strict --deep "$app" || stop "the signature of Kubedog.app isn't right"

    if [ "$2" = 1 ]; then
        # Both in one question. The answer is fixed to the app, so it's also known on a Mac without internet.
        mkdir "$m/ask"
        ditto "$app" "$m/ask/Kubedog.app"
        cp "$m/alone/kubedog" "$m/ask/kubedog"
        ditto -c -k "$m/ask" "$m/ask.zip"
        apple_checks "$m/ask.zip"
        xcrun stapler staple -q "$app" || stop "Apple's answer couldn't be fixed to Kubedog.app"
    fi

    ln -s /Applications "$m/dmg/Applications"
    hdiutil create -quiet -volname "Kubedog $V" -srcfolder "$m/dmg" -fs HFS+ -format UDZO -ov "$dmg"
    codesign --force "$stamp" -s "$SIGN_ID" "$dmg"
    if [ "$2" = 1 ]; then
        apple_checks "$dmg"
        xcrun stapler staple -q "$dmg" || stop "Apple's answer couldn't be fixed to the disk image"
        spctl -a -t open --context context:primary-signature "$dmg" || stop "macOS wouldn't open the disk image without a warning"
        spctl -a -t exec "$app" || stop "macOS wouldn't open Kubedog.app without a warning"
    fi
    pack macos-arm64 "$m/alone/kubedog" tar
    rm -rf "$m"
}
sums() { (cd "$DIST" && shasum -a 256 kubedog-* > SHA256SUMS); }

if [ "$NOTARIZE" = 1 ]; then mac_pack apple 1; else mac_pack none 0; fi
pack linux-amd64   target/x86_64-unknown-linux-gnu/release/kubedog   tar
pack linux-arm64   target/aarch64-unknown-linux-gnu/release/kubedog  tar
pack windows-x64   target/x86_64-pc-windows-gnu/release/kubedog.exe  zip
pack windows-arm64 target/aarch64-pc-windows-gnullvm/release/kubedog.exe zip

say "kubectl $KUBECTL_VERSION for the Windows installer"
# Taken from Kubernetes' own downloads and checked against the checksum published next to it. Kept between
# runs, so a release can be made again without the internet once these are here.
kubectl_for() { # kubectl_for <amd64|arm64>
    local dir="$ROOT/target/kubectl/$KUBECTL_VERSION/$1" url="https://dl.k8s.io/release/$KUBECTL_VERSION/bin/windows/$1/kubectl.exe"
    mkdir -p "$dir"
    [ -s "$dir/kubectl.exe" ] || curl -fsSL "$url" -o "$dir/kubectl.exe"
    [ -s "$dir/kubectl.exe.sha256" ] || curl -fsSL "$url.sha256" -o "$dir/kubectl.exe.sha256"
    [ "$(shasum -a 256 "$dir/kubectl.exe" | cut -d' ' -f1)" = "$(tr -d '[:space:]' < "$dir/kubectl.exe.sha256")" ] \
        || stop "kubectl for Windows $1 doesn't match its checksum; delete $dir and run again"
}
kubectl_for amd64
kubectl_for arm64

say "Windows installer"
# One for every Windows computer: it holds both programs and installs the one that fits.
K="$ROOT/target/kubectl/$KUBECTL_VERSION"
makensis -V2 -DVERSION="$V" -DROOT="$ROOT" \
    -DEXE_AMD64="$ROOT/target/x86_64-pc-windows-gnu/release/kubedog.exe" \
    -DEXE_ARM64="$ROOT/target/aarch64-pc-windows-gnullvm/release/kubedog.exe" \
    -DKUBECTL_AMD64="$K/amd64/kubectl.exe" -DKUBECTL_ARM64="$K/arm64/kubectl.exe" -DKUBECTL_VERSION="$KUBECTL_VERSION" \
    -DNOTICES="$NOTICES" -DOUT="$DIST/kubedog-$V-windows-setup.exe" scripts/windows-installer.nsi
sums

say "Checks on what was built"
[ "$(target/aarch64-apple-darwin/release/kubedog --version)" = "kubedog $V" ] || stop "the Mac build doesn't say version $V"
codesign -v target/aarch64-apple-darwin/release/kubedog || stop "the Mac build isn't signed (not even by the linker)"
# Nothing of this computer, and nothing from the list of names that must never be published
# (plans/never-publish.txt: one word or name per line; the file itself is never committed).
PROGRAMS=(target/aarch64-apple-darwin/release/kubedog target/x86_64-unknown-linux-gnu/release/kubedog
          target/aarch64-unknown-linux-gnu/release/kubedog target/x86_64-pc-windows-gnu/release/kubedog.exe
          target/aarch64-pc-windows-gnullvm/release/kubedog.exe)
for p in "${PROGRAMS[@]}"; do
    if strings -a "$p" | grep -F -m3 -e "$HOME" -e "/Users/$USER/"; then stop "$p holds a path of this computer"; fi
    if [ -s plans/never-publish.txt ] && strings -a "$p" | grep -i -F -m3 -f plans/never-publish.txt; then
        stop "$p holds a name from plans/never-publish.txt"
    fi
done
[ -s plans/never-publish.txt ] || echo "Note: no plans/never-publish.txt, so only this computer's paths were looked for."

say "Made, in target/dist"
(cd "$DIST" && ls -lh kubedog-* | awk '{print "  " $5 "\t" $9}' && echo && cat SHA256SUMS)

if [ "$BUILD_ONLY" = 1 ]; then
    echo
    if [ "$NOTARIZE" = 1 ]; then
        echo "Build only: the Mac app was checked by Apple; nothing was published."
    else
        echo "Build only: nothing was uploaded. The Mac files are signed but not checked by Apple (--notarize does that)."
    fi
    exit 0
fi

echo
echo "Next: the Mac app goes to Apple for its check (the two Mac files and their checksums change with that),"
echo "then: the tag $TAG, a release $TAG on github.com/$GH_REPO, and the formula and cask in $TAP_REPO."
printf 'Type the version (%s) to go on, anything else to stop: ' "$V"
read -r answer
[ "$answer" = "$V" ] || stop "nothing was uploaded"

say "macOS: signed and checked by Apple"
mac_pack apple 1
sums
(cd "$DIST" && grep macos SHA256SUMS)

sum() { grep "  kubedog-$V-$1\$" "$DIST/SHA256SUMS" | cut -d' ' -f1; }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

say "Tag and release"
git tag -a "$TAG" -m "Kubedog $V"
git push -q origin "$TAG"
NOTES="$WORK/notes.md"
if [ -f "plans/release-notes-$V.md" ]; then cp "plans/release-notes-$V.md" "$NOTES"; else : > "$NOTES"; fi
cat >> "$NOTES" <<NOTES_END

**Install:** on a Mac (Apple silicon) \`brew install --cask pezzking/tap/kubedog-app\`, or the \`.dmg\` below, signed and checked by Apple. For Linux and Windows, take the file for your system below. See the [README](https://github.com/$GH_REPO#install).

macOS: built and used daily. Linux and Windows: built, not yet tried by hand on a real desktop.
NOTES_END
gh release create "$TAG" --repo "$GH_REPO" --verify-tag --title "Kubedog $V" --notes-file "$NOTES" \
    "$DIST"/kubedog-"$V"-*.dmg "$DIST"/kubedog-"$V"-*.tar.gz "$DIST"/kubedog-"$V"-*-setup.exe "$DIST"/kubedog-"$V"-*.zip "$DIST/SHA256SUMS"

say "Homebrew formula and cask"
gh repo clone "$TAP_REPO" "$WORK/tap" -- -q
mkdir -p "$WORK/tap/Formula" "$WORK/tap/Casks"
BASE="https://github.com/$GH_REPO/releases/download/$TAG"
cat > "$WORK/tap/Formula/kubedog.rb" <<FORMULA_END
# Written by Kubedog's release script; changes made here by hand are lost with the next release.
class Kubedog < Formula
  desc "Fast desktop app for Kubernetes clusters"
  homepage "https://github.com/$GH_REPO"
  license "Apache-2.0"

  on_macos do
    depends_on arch: :arm64
    on_arm do
      url "$BASE/kubedog-$V-macos-arm64.tar.gz"
      sha256 "$(sum macos-arm64.tar.gz)"
    end
  end

  on_linux do
    on_intel do
      url "$BASE/kubedog-$V-linux-amd64.tar.gz"
      sha256 "$(sum linux-amd64.tar.gz)"
    end
    on_arm do
      url "$BASE/kubedog-$V-linux-arm64.tar.gz"
      sha256 "$(sum linux-arm64.tar.gz)"
    end
  end

  def install
    bin.install "kubedog"
    doc.install "THIRD-PARTY.md", "THIRD-PARTY-LIBRARIES.txt", "licenses"
  end

  def caveats
    <<~EOS
      Kubedog uses your own kubectl. If you don't have it yet:
        brew install kubernetes-cli
      Start it with: kubedog
    EOS
  end

  test do
    assert_equal "kubedog #{version}", shell_output("#{bin}/kubedog --version").strip
  end
end
FORMULA_END
# The app for the Applications folder; the formula above gives the command.
cat > "$WORK/tap/Casks/kubedog-app.rb" <<CASK_END
# Written by Kubedog's release script; changes made here by hand are lost with the next release.
cask "kubedog-app" do
  version "$V"
  sha256 "$(sum macos-arm64.dmg)"

  url "$BASE/kubedog-$V-macos-arm64.dmg"
  name "Kubedog"
  desc "Fast desktop app for Kubernetes clusters"
  homepage "https://github.com/$GH_REPO"

  depends_on arch: :arm64

  app "Kubedog.app"
end
CASK_END
git -C "$WORK/tap" add Formula/kubedog.rb Casks/kubedog-app.rb
# With the name and address this repository commits with, not the computer's own.
git -C "$WORK/tap" -c user.name="$(git config user.name)" -c user.email="$(git config user.email)" commit -q -m "kubedog $V"
git -C "$WORK/tap" push -q origin HEAD

say "Done: https://github.com/$GH_REPO/releases/tag/$TAG"
echo "Try it: brew update && brew install --cask pezzking/tap/kubedog-app"
