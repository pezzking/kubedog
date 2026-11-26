//! Kubedog's logo, from assets/icons: the window and Dock icon, and the mark inside the app.

/// The logo's PNGs: (pixels, file).
static PNGS: [(u32, &[u8]); 5] = [
    (32, include_bytes!("../assets/icons/kubedog-32.png")),
    (48, include_bytes!("../assets/icons/kubedog-48.png")),
    (64, include_bytes!("../assets/icons/kubedog-64.png")),
    (128, include_bytes!("../assets/icons/kubedog-128.png")),
    (512, include_bytes!("../assets/icons/kubedog-512.png")),
];

/// The smallest picture that's at least this many pixels wide: its size and straight RGBA pixels.
pub fn rgba(at_least: u32) -> (u32, Vec<u8>) {
    let (size, png) = PNGS.iter().find(|p| p.0 >= at_least).unwrap_or(&PNGS[PNGS.len() - 1]);
    match image::load_from_memory_with_format(png, image::ImageFormat::Png) {
        Ok(i) => (*size, i.to_rgba8().into_raw()),
        // The pictures are part of the program (and tested), so this doesn't happen.
        Err(_) => (1, vec![0, 0, 0, 0]),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn logos_decode() {
        for (size, _) in super::PNGS {
            let (n, px) = super::rgba(size);
            assert_eq!((n, px.len()), (size, (size * size * 4) as usize));
            // See-through corner, solid middle.
            assert_eq!(px[3], 0, "{size}");
            assert_eq!(px[((size / 2 * size + size / 2) * 4 + 3) as usize], 255, "{size}");
        }
        assert_eq!(super::rgba(33).0, 48);
        assert_eq!(super::rgba(4000).0, 512);
    }
}
