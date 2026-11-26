# Third-party notices

Kubedog is licensed under the Apache License 2.0 (see `LICENSE`). It's built with, and partly began from, work by
others. Their notices are here and in the files named below.

## PathViz

Parts of the packet decoder in the Network Lab (`src/app/packets.rs`: IP, DNS, HTTP and TLS) began as a rewrite in Rust of parts of
[PathViz](https://github.com/iximiuz/pathviz) by Ivan Velichko.

```
MIT License

Copyright (c) 2026 Ivan Velichko

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## kubectl

The Windows installers can bring `kubectl.exe` along, for computers that have none. It's the unchanged program
from the Kubernetes project (<https://kubernetes.io>, Apache License 2.0, the same licence as in `LICENSE`),
taken from its own downloads and checked against its published checksum when a release is made.

## kubectl cnpg

The Windows installer can also bring the CloudNativePG plugin for kubectl (`kubectl-cnpg.exe`), for the Postgres
page. It's the unchanged program from the CloudNativePG project (<https://cloudnative-pg.io>, Apache License 2.0),
taken from its own release and checked against the checksums published with it when a release is made.

## Fonts

The fonts that can be chosen in Settings come with Kubedog, each under the SIL Open Font License 1.1. The full text
for each is in `assets/fonts/` (in a download: the `licenses` folder):

| Font | Licence file |
|---|---|
| Inter | `Inter-OFL.txt` |
| IBM Plex Sans | `IBMPlexSans-OFL.txt` |
| Atkinson Hyperlegible | `AtkinsonHyperlegible-OFL.txt` |
| JetBrains Mono | `JetBrainsMono-OFL.txt` |

DejaVu Sans also comes with Kubedog, unchanged, for symbols (arrows, ticks, triangles) on systems whose own fonts
lack them. It's free to use and pass on under the Bitstream Vera licence; DejaVu's own changes are in the public
domain. The full text is in `DejaVuSans-LICENSE.txt`, in the same place.

The window toolkit (egui) brings fonts of its own (Ubuntu, Hack, Noto Emoji and an icon font); their licences are in
the list of libraries.

## Libraries

Every Rust library Kubedog is built with, with its licence's text, is listed in `THIRD-PARTY-LIBRARIES.txt`, which
comes with every download. It's made from `Cargo.lock` when a release is built (`scripts/release.sh`, with
`cargo about`), so it always matches what's in the program.
