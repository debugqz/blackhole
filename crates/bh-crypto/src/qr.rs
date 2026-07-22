//! Shared SVG QR rendering, factored out once a third caller
//! (`payment_address`) needed the same "arbitrary string -> scannable SVG"
//! helper `safety_number`/`invite` already had duplicated.

use qrcode::render::svg;
use qrcode::QrCode;

use crate::CryptoError;

/// SVG markup for a scannable QR code of `data`.
pub fn to_svg(data: &str) -> Result<String, CryptoError> {
    let code = QrCode::new(data.as_bytes())
        .map_err(|_| CryptoError::NotImplemented("qr: encoding failed"))?;
    Ok(code
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_well_formed_svg() {
        assert!(to_svg("hello").unwrap().contains("<svg"));
    }
}
