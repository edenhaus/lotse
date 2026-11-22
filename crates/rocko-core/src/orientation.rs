//! How a stream's picture is turned for display: eight transforms,
//! numbered 1 to 8 and named for what each does to the picture.
//!
//! The numbers follow the EXIF orientation tag's values, and each value
//! names the turn applied for display. For 6 and 8 that turn is the
//! opposite of the EXIF tag's: 6 turns the picture a quarter
//! counterclockwise and 8 a quarter clockwise, the convention of the
//! orientation settings clients already store, so a camera keeps the look
//! its setting gives it.
//! Core only names the transform; an output decides how to carry it.

/// A display transform of the picture, numbered 1 to 8 ([`Self::code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Orientation {
    /// 1: shown as the camera sends it.
    #[default]
    NoTransform,
    /// 2: mirrored left to right (ffmpeg `hflip`).
    Mirror,
    /// 3: turned half way round.
    Rotate180,
    /// 4: flipped top to bottom (ffmpeg `vflip`).
    Flip,
    /// 5: turned a quarter counterclockwise, then flipped top to bottom
    /// (`transpose=2,vflip`): a transpose about the main diagonal.
    RotateLeftAndFlip,
    /// 6: turned a quarter counterclockwise.
    RotateLeft,
    /// 7: turned a quarter clockwise, then flipped top to bottom
    /// (`transpose=1,vflip`): a transpose about the anti-diagonal.
    RotateRightAndFlip,
    /// 8: turned a quarter clockwise.
    RotateRight,
}

impl Orientation {
    /// Every orientation, in the order of its number.
    pub const ALL: [Self; 8] = [
        Self::NoTransform,
        Self::Mirror,
        Self::Rotate180,
        Self::Flip,
        Self::RotateLeftAndFlip,
        Self::RotateLeft,
        Self::RotateRightAndFlip,
        Self::RotateRight,
    ];

    /// Its number, 1 to 8.
    pub const fn code(self) -> u8 {
        match self {
            Self::NoTransform => 1,
            Self::Mirror => 2,
            Self::Rotate180 => 3,
            Self::Flip => 4,
            Self::RotateLeftAndFlip => 5,
            Self::RotateLeft => 6,
            Self::RotateRightAndFlip => 7,
            Self::RotateRight => 8,
        }
    }

    /// The orientation numbered `code`, or `None` outside 1 to 8.
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|orientation| orientation.code() == code)
    }

    /// Its name, lowercase: the control API's spelling.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoTransform => "no_transform",
            Self::Mirror => "mirror",
            Self::Rotate180 => "rotate_180",
            Self::Flip => "flip",
            Self::RotateLeftAndFlip => "rotate_left_and_flip",
            Self::RotateLeft => "rotate_left",
            Self::RotateRightAndFlip => "rotate_right_and_flip",
            Self::RotateRight => "rotate_right",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    #[test]
    fn codes_and_names_are_the_eight_orientations() {
        let expected = [
            (1, "no_transform"),
            (2, "mirror"),
            (3, "rotate_180"),
            (4, "flip"),
            (5, "rotate_left_and_flip"),
            (6, "rotate_left"),
            (7, "rotate_right_and_flip"),
            (8, "rotate_right"),
        ];
        for (orientation, (code, name)) in Orientation::ALL.into_iter().zip(expected) {
            assert_eq!((orientation.code(), orientation.name()), (code, name));
            assert_eq!(Orientation::from_code(code), Some(orientation));
        }
        assert_eq!(Orientation::default(), Orientation::NoTransform);
    }

    #[test]
    fn codes_outside_one_to_eight_are_none() {
        for code in [0, 9, u8::MAX] {
            assert_eq!(Orientation::from_code(code), None);
        }
    }
}
