//! Zyth — bright monochrome UI with Vercel code-snippet colors.
//!
//! A polished black–white–gray UI inspired by Zyth’s design system:
//! true black canvas, tight gray surface steps, white accents, and
//! restrained semantic color only where it improves readability
//! (errors, success, diffs). Neutral grays quantize cleanly, so this
//! theme stays usable on 256-color terminals.

use ratatui::style::{Color, Modifier};

use super::tokyonight::Theme;

/// Helper for concise const `Color::Rgb` definitions.
const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

// Zyth / Geist monochrome ramp (dark).
// Surfaces step carefully so chrome hierarchy stays legible without color.
#[allow(dead_code)]
mod palette {
    use super::*;

    // ── Backgrounds (pure black OLED) ────────────────────────────────────
    pub const BLACK: Color = rgb(0, 0, 0); // #000000 — canvas
    pub const GRAY1: Color = rgb(10, 10, 10); // #0a0a0a — sunken / track
    pub const GRAY2: Color = rgb(17, 17, 17); // #111111 — elevated
    pub const GRAY3: Color = rgb(23, 23, 23); // #171717 — highlight
    pub const GRAY4: Color = rgb(28, 28, 28); // #1c1c1c — hover
    pub const GRAY5: Color = rgb(38, 38, 38); // #262626 — visual / selection
    pub const GRAY6: Color = rgb(51, 51, 51); // #333333 — borders, thumb
    pub const GRAY7: Color = rgb(100, 100, 100); // #646464 — dim chrome
    pub const GRAY8: Color = rgb(150, 150, 150); // #969696 — medium muted
    pub const GRAY9: Color = rgb(190, 190, 190); // #bebebe — secondary labels
    // Text hierarchy (bright OLED): pure white is reserved for focus accents /
    // H1 so body copy can sit one step softer and avoid halation on #000.
    pub const GRAY10: Color = rgb(230, 230, 230); // #e6e6e6 — secondary text
    pub const GRAY11: Color = rgb(250, 250, 250); // #fafafa — primary body (Vercel fg-ish)
    pub const WHITE: Color = rgb(255, 255, 255); // #ffffff — max-contrast accents

    // ── Semantic (minimal — only where monochrome fails UX) ──────────────
    // Soft, desaturated reds/greens so they sit with the monochrome UI.
    pub const ERROR: Color = rgb(255, 99, 105); // #ff6369 — Vercel error
    pub const ERROR_BG: Color = rgb(42, 14, 16); // #2a0e10
    pub const SUCCESS: Color = rgb(80, 227, 194); // #50e3c2 — Vercel string/mint
    pub const SUCCESS_BG: Color = rgb(10, 31, 18); // #0a1f12
    pub const WARNING: Color = rgb(245, 166, 35); // #f5a623 — Vercel number/amber
}
use palette::*;

impl Theme {
    /// Zyth monochrome — pure black canvas, gray surface ramp, white accents.
    ///
    /// Colors are defined in RGB. Call [`Theme::quantized`] to downgrade
    /// them to the terminal's supported color level before rendering.
    pub const fn zyth() -> Self {
        Self {
            // Canvas + surfaces
            bg_base: BLACK,
            bg_light: GRAY2,       // elevated panels / user blocks
            bg_dark: GRAY1,        // sunken code blocks
            bg_highlight: GRAY3,   // highlight rows
            bg_hover: GRAY4,       // mouse hover
            bg_terminal: BLACK,

            // Accents — monochrome identity; pure white leads the eye
            accent_user: WHITE,
            accent_assistant: GRAY11,
            accent_thinking: GRAY9,
            accent_tool: GRAY9,
            accent_system: GRAY10,
            accent_error: ERROR,
            accent_success: SUCCESS,
            accent_running: WHITE,
            accent_skill: GRAY10,

            // Body text: near-white primary, bright secondary (not muddy mid-gray)
            text_primary: GRAY11,
            text_secondary: GRAY10,

            gray_dim: GRAY7,
            gray: GRAY8,
            gray_bright: GRAY10,

            // Semantic content (restrained)
            command: rgb(255, 0, 128), // #FF0080 Vercel keyword pink
            path: rgb(0, 223, 216), // #00DFD8 Vercel type cyan
            running: WHITE,
            warning: WARNING,

            fuzzy_accent: rgb(50, 145, 255), // #3291FF Vercel blue

            accent_plan: WHITE,

            accent_verify: GRAY10,

            accent_feedback: SUCCESS,

            accent_remember: SUCCESS,

            // Chrome borders — pure white prompt frame (idle + focused)
            selection_border: GRAY6,
            hover_border: GRAY5,
            prompt_border: WHITE,
            prompt_border_active: WHITE,

            accent_model: GRAY10,

            // Scrollbar: dark track, clearly lighter thumb (ΣΔ ≥ 30)
            scrollbar_bg: GRAY1, // Σ 30
            scrollbar_fg: GRAY6, // Σ 153 → Δ 123

            // Diffs — only place with real color, essential for review UX
            diff_delete_bg: ERROR_BG,
            diff_delete_fg: ERROR,
            diff_insert_bg: SUCCESS_BG,
            diff_insert_fg: SUCCESS,
            diff_equal_fg: GRAY8,
            diff_gutter_fg: GRAY7,

            bg_visual: GRAY5,

            paste_bg: GRAY1,
            paste_fg: GRAY10,
            paste_dim: GRAY7,

            // Markdown — monochrome heading ladder (weight via brightness)
            md_heading_h1: WHITE,
            md_heading_h1_mod: Modifier::BOLD,
            md_heading_h2: WHITE,
            md_heading_h2_mod: Modifier::BOLD,
            md_heading_h3: GRAY11,
            md_heading_h3_mod: Modifier::BOLD,
            md_heading_h4: GRAY10,
            md_heading_h4_mod: Modifier::BOLD,
            md_heading_h5: GRAY9,
            md_heading_h5_mod: Modifier::BOLD,
            md_heading_h6: GRAY9,
            md_heading_h6_mod: Modifier::empty(),
            // Inline code uses Vercel function blue (snippet-accurate)
            md_code: rgb(50, 145, 255), // #3291FF
            md_task_checked: SUCCESS,
            md_task_unchecked: GRAY10,
            md_muted: GRAY9,
            md_code_bg: BLACK, // pure black like Vercel code blocks
            md_text: GRAY11,
            // Links: Vercel blue
            link_fg: rgb(50, 145, 255), // #3291FF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zyth_is_dark_pure_black() {
        let theme = Theme::zyth();
        assert!(matches!(theme.bg_base, Color::Rgb(0, 0, 0)));
        assert!(theme.is_dark());
        assert!(matches!(theme.accent_user, Color::Rgb(255, 255, 255)));
        assert!(matches!(theme.text_primary, Color::Rgb(250, 250, 250)));
    }

    #[test]
    fn zyth_scrollbar_thumb_above_track() {
        let theme = Theme::zyth();
        let Color::Rgb(tr, tg, tb) = theme.scrollbar_bg else {
            panic!("expected RGB track");
        };
        let Color::Rgb(hr, hg, hb) = theme.scrollbar_fg else {
            panic!("expected RGB thumb");
        };
        let track = tr as i32 + tg as i32 + tb as i32;
        let thumb = hr as i32 + hg as i32 + hb as i32;
        assert!(
            thumb - track >= 30,
            "thumb Σ{thumb} must be ≥30 lighter than track Σ{track}"
        );
    }
}
