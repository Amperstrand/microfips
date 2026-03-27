const END: u8 = 0xC0;
const ESC: u8 = 0xDB;
const ESC_END: u8 = 0xDC;
const ESC_ESC: u8 = 0xDD;

pub const MAX_FRAME_SIZE: usize = 1280;

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    FrameTooLong,
}

enum DecodeState {
    Normal,
    Escaped,
}

pub struct SlipDecoder {
    state: DecodeState,
    pos: usize,
}

impl Default for SlipDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SlipDecoder {
    pub const fn new() -> Self {
        Self {
            state: DecodeState::Normal,
            pos: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = DecodeState::Normal;
        self.pos = 0;
    }

    pub fn feed<'a>(
        &mut self,
        byte: u8,
        buf: &'a mut [u8],
    ) -> Result<Option<&'a [u8]>, DecodeError> {
        match self.state {
            DecodeState::Normal => match byte {
                END => {
                    if self.pos > 0 {
                        let frame = &buf[..self.pos];
                        self.pos = 0;
                        Ok(Some(frame))
                    } else {
                        Ok(None)
                    }
                }
                ESC => {
                    self.state = DecodeState::Escaped;
                    Ok(None)
                }
                b => {
                    if self.pos >= buf.len() {
                        self.pos = 0;
                        self.state = DecodeState::Normal;
                        return Err(DecodeError::FrameTooLong);
                    }
                    buf[self.pos] = b;
                    self.pos += 1;
                    Ok(None)
                }
            },
            DecodeState::Escaped => {
                let decoded = match byte {
                    ESC_END => END,
                    ESC_ESC => ESC,
                    _ => {
                        self.state = DecodeState::Normal;
                        self.pos = 0;
                        return Err(DecodeError::FrameTooLong);
                    }
                };
                if self.pos >= buf.len() {
                    self.pos = 0;
                    self.state = DecodeState::Normal;
                    return Err(DecodeError::FrameTooLong);
                }
                buf[self.pos] = decoded;
                self.pos += 1;
                self.state = DecodeState::Normal;
                Ok(None)
            }
        }
    }

    pub fn encode(input: &[u8], output: &mut [u8]) -> usize {
        let mut out_pos = 0;
        if out_pos < output.len() {
            output[out_pos] = END;
            out_pos += 1;
        }
        for &b in input {
            match b {
                END => {
                    if out_pos + 1 < output.len() {
                        output[out_pos] = ESC;
                        output[out_pos + 1] = ESC_END;
                        out_pos += 2;
                    }
                }
                ESC => {
                    if out_pos + 1 < output.len() {
                        output[out_pos] = ESC;
                        output[out_pos + 1] = ESC_ESC;
                        out_pos += 2;
                    }
                }
                _ => {
                    if out_pos < output.len() {
                        output[out_pos] = b;
                        out_pos += 1;
                    }
                }
            }
        }
        if out_pos < output.len() {
            output[out_pos] = END;
            out_pos += 1;
        }
        out_pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn encode_decode_roundtrip(input: &[u8]) -> Vec<u8> {
        let mut encoded = vec![0u8; input.len() * 2 + 2];
        let enc_len = SlipDecoder::encode(input, &mut encoded);
        let mut decoder = SlipDecoder::new();
        let mut decoded = Vec::new();
        let mut buf = [0u8; MAX_FRAME_SIZE];
        for &byte in &encoded[..enc_len] {
            if let Ok(Some(frame)) = decoder.feed(byte, &mut buf) {
                decoded.extend_from_slice(frame);
            }
        }
        decoded
    }

    #[test]
    fn decode_empty_between_ends() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 128];
        assert_eq!(decoder.feed(END, &mut buf), Ok(None));
        assert_eq!(decoder.feed(END, &mut buf), Ok(None));
    }

    #[test]
    fn decode_single_byte_frame() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 128];
        assert_eq!(decoder.feed(0x41, &mut buf), Ok(None));
        assert_eq!(decoder.feed(END, &mut buf), Ok(Some(&[0x41][..])));
    }

    #[test]
    fn decode_escaped_end() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 128];
        assert_eq!(decoder.feed(END, &mut buf), Ok(None));
        assert_eq!(decoder.feed(ESC, &mut buf), Ok(None));
        assert_eq!(decoder.feed(ESC_END, &mut buf), Ok(None));
        assert_eq!(decoder.feed(END, &mut buf), Ok(Some(&[END][..])));
    }

    #[test]
    fn decode_escaped_esc() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 128];
        assert_eq!(decoder.feed(END, &mut buf), Ok(None));
        assert_eq!(decoder.feed(ESC, &mut buf), Ok(None));
        assert_eq!(decoder.feed(ESC_ESC, &mut buf), Ok(None));
        assert_eq!(decoder.feed(END, &mut buf), Ok(Some(&[ESC][..])));
    }

    #[test]
    fn decode_invalid_escape() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 128];
        assert_eq!(decoder.feed(ESC, &mut buf), Ok(None));
        assert_eq!(decoder.feed(0x00, &mut buf), Err(DecodeError::FrameTooLong));
    }

    #[test]
    fn decode_frame_too_long() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 4];
        for b in [0x01, 0x02, 0x03, 0x04, 0x05] {
            let _ = decoder.feed(b, &mut buf);
        }
    }

    #[test]
    fn decode_reset_after_error() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 128];
        let _ = decoder.feed(ESC, &mut buf);
        let _ = decoder.feed(0x00, &mut buf);
        assert_eq!(decoder.feed(0x42, &mut buf), Ok(None));
        assert_eq!(decoder.feed(END, &mut buf), Ok(Some(&[0x42][..])));
    }

    #[test]
    fn encode_with_end_byte() {
        let input = &[0xC0, 0xDB];
        let mut output = [0u8; 256];
        let len = SlipDecoder::encode(input, &mut output);
        assert_eq!(&output[..len], &[0xC0, 0xDB, 0xDC, 0xDB, 0xDD, 0xC0]);
    }

    #[test]
    fn encode_with_esc_byte() {
        let input = &[0xDB];
        let mut output = [0u8; 256];
        let len = SlipDecoder::encode(input, &mut output);
        assert_eq!(&output[..len], &[0xC0, 0xDB, 0xDD, 0xC0]);
    }

    #[test]
    fn roundtrip_simple() {
        assert_eq!(encode_decode_roundtrip(b"hello world"), b"hello world");
    }

    #[test]
    fn roundtrip_special_bytes() {
        let input: &[u8] = &[0xC0, 0xDB, 0x00, 0xFF, 0xC0, 0xDB];
        assert_eq!(encode_decode_roundtrip(input), input);
    }

    #[test]
    fn roundtrip_empty() {
        assert!(encode_decode_roundtrip(&[]).is_empty());
    }

    #[test]
    fn roundtrip_single_byte() {
        assert_eq!(encode_decode_roundtrip(&[0x42]), &[0x42]);
    }

    #[test]
    fn roundtrip_all_special() {
        assert_eq!(
            encode_decode_roundtrip(&[0xC0, 0xDB, 0xDC, 0xDD]),
            &[0xC0, 0xDB, 0xDC, 0xDD]
        );
    }

    #[test]
    fn roundtrip_binary_data() {
        let input: Vec<u8> = (0u8..=255).collect();
        assert_eq!(encode_decode_roundtrip(&input), input);
    }

    #[test]
    fn multiple_frames() {
        let mut decoder = SlipDecoder::new();
        let mut buf = [0u8; 128];
        assert_eq!(decoder.feed(0x41, &mut buf), Ok(None));
        assert_eq!(decoder.feed(END, &mut buf), Ok(Some(&[0x41][..])));
        assert_eq!(decoder.feed(0x42, &mut buf), Ok(None));
        assert_eq!(decoder.feed(0x43, &mut buf), Ok(None));
        assert_eq!(decoder.feed(END, &mut buf), Ok(Some(&[0x42, 0x43][..])));
    }
}
