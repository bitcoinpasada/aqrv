//! The Argon QR Vault's own wording: every string `aqrv-app` and
//! `aqrv-desktop` show, in one file. The Windows build scripts read
//! `aqrv_window_title` and `aqrv_publisher` from it as text, so each is a
//! plain `name: "value",` line.

/// The struct of every string and the English static, from one list: each
/// key's doc, then its value.
macro_rules! strings {
    ($( $(#[doc = $doc:expr])* $name:ident: $value:expr, )*) => {
        /// Every string the Argon QR Vault shows.
        pub struct Strings {
            $( $(#[doc = $doc])* pub $name: &'static str, )*
        }

        /// The English wording.
        pub static STRINGS: Strings = Strings {
            $( $name: $value, )*
        };
    };
}

strings! {
    /// The Argon QR Vault's tab for making a code.
    aqrv_tab_make: "Make",
    /// The Argon QR Vault's tab for opening a code.
    aqrv_tab_open: "Open",
    /// Make, the item: the choice to type an item.
    aqrv_type_own: "Type my own",
    /// Make, the item: the card's title.
    aqrv_test_data_title: "Test data only",
    /// Make, the item: the card's line.
    aqrv_test_data_line: "Samples and typed test items are not for real funds.",
    /// Make, the item: the typed item's field label.
    aqrv_own_field: "Item",
    /// A kind of typed item: BIP-39 entropy as hex.
    aqrv_kind_entropy: "Seed entropy (hex)",
    /// A kind of typed item.
    aqrv_kind_codex32: "codex32 string",
    /// A kind of typed item.
    aqrv_kind_passphrase: "BIP-39 passphrase",
    /// A kind of typed item.
    aqrv_kind_note: "Note",
    /// A kind of typed item: a 32-byte key as hex.
    aqrv_kind_raw_key: "Raw key (hex)",
    /// Make, the item: a typed item that is not valid for its kind.
    aqrv_not_an_item: "Not a valid item",
    /// The button to the next step.
    aqrv_next: "Next",
    /// The button to the previous step.
    aqrv_back: "Back",
    /// A sample's name.
    aqrv_sample_words12: "12 words, abandon … about",
    /// A sample's name.
    aqrv_sample_words24: "24 words, zoo … vote",
    /// A sample's name.
    aqrv_sample_codex_secret: "codex32 secret (BIP 93 vector 1)",
    /// A sample's name.
    aqrv_sample_codex_share: "codex32 share (BIP 93 vector 2)",
    /// A sample's name.
    aqrv_sample_note: "Note",
    /// A sample's name.
    aqrv_sample_passphrase: "BIP-39 passphrase",
    /// A sample's name.
    aqrv_sample_raw_key: "Raw key",
    /// A sample's type, under its name.
    aqrv_type_words12: "BIP-39 entropy, 12 words",
    /// A sample's type, under its name.
    aqrv_type_words24: "BIP-39 entropy, 24 words",
    /// A sample's type, under its name.
    aqrv_type_codex32: "codex32 string",
    /// A sample's type, under its name.
    aqrv_type_note: "Note",
    /// A sample's type, under its name.
    aqrv_type_passphrase: "BIP-39 passphrase",
    /// A sample's type, under its name.
    aqrv_type_raw_key: "32-byte key",
    /// Make, the settings: the size heading.
    aqrv_settings_size: "Size",
    /// A code size: the 32-byte one.
    aqrv_size_25: "25 × 25 · 4-byte tag",
    /// A made code's text form, as the hex bytes have a label.
    aqrv_text: "Text",
    /// A code size: the small one.
    aqrv_size_29: "29 × 29 · 4-byte tag",
    /// A code size: the large one.
    aqrv_size_33: "33 × 33 · 8-byte tag",
    /// A code size: the 37-byte one, which is words and a file only.
    aqrv_size_words: "36 words · no QR code · 4-byte tag",
    /// A made code without a QR code: its form and length. `{}`: the
    /// number of words, then of bytes.
    aqrv_words_label: "{} words · {} bytes",
    /// A made code's words heading.
    aqrv_words: "Words",
    /// One word of a list. `{}`: its number from 1, then the word.
    aqrv_word_numbered: "{}. {}",
    /// The button that puts the words on the clipboard.
    aqrv_copy_words: "Copy words",
    /// The words are on the clipboard.
    aqrv_words_copied: "Words copied",
    /// The words could not be put on the clipboard.
    aqrv_words_not_copied: "The words could not be copied",
    /// Make, the settings: the memory heading.
    aqrv_settings_memory: "Memory",
    /// A memory step's row. `{}`: the memory, then the time.
    aqrv_memory_row: "{} · about {}",
    /// Marks the suggested memory step.
    aqrv_memory_suggested: "Suggested",
    /// A memory step.
    aqrv_memory_64: "64 MiB",
    /// A memory step.
    aqrv_memory_128: "128 MiB",
    /// A memory step.
    aqrv_memory_256: "256 MiB",
    /// A memory step.
    aqrv_memory_512: "512 MiB",
    /// A memory step.
    aqrv_memory_1g: "1 GiB",
    /// A time. `{}`: whole seconds.
    aqrv_seconds: "{} s",
    /// The memory rows' time while the timing run has not finished.
    aqrv_timing: "timing",
    /// Make, the settings: the passphrase field's label.
    aqrv_passphrase: "Passphrase",
    /// Make, the settings: the second passphrase field's label.
    aqrv_passphrase_again: "Passphrase again",
    /// Make, the settings: the two passphrases are not the same.
    aqrv_passphrase_differ: "The two passphrases differ",
    /// Make, the settings: under the passphrase.
    aqrv_passphrase_strength: "The code is only as strong as its passphrase",
    /// Shows a passphrase typed.
    aqrv_show: "Show",
    /// Hides a passphrase typed.
    aqrv_hide: "Hide",
    /// The button that makes the code.
    aqrv_make: "Make code",
    /// Make, working. `{}`: the memory.
    aqrv_working: "Using {}",
    /// Cancels the work and discards its result.
    aqrv_cancel: "Cancel",
    /// Make, the code: what the QR is. `{}` in order: its version, modules
    /// across, modules down, its error-correction level, its mode, the
    /// envelope's bytes.
    aqrv_code_label: "Version {} · {} × {} · Level {} · {} · {} bytes",
    /// Make, the code: the lowest error-correction level's letter.
    aqrv_level_l: "L",
    /// Make, the code: the medium error-correction level's letter.
    aqrv_level_m: "M",
    /// Make, the code: the quartile error-correction level's letter.
    aqrv_level_q: "Q",
    /// Make, the code: the highest error-correction level's letter.
    aqrv_level_h: "H",
    /// Make, the code: the QR's byte mode.
    aqrv_mode_byte: "Byte",
    /// Make, the code: the QR's alphanumeric mode.
    aqrv_mode_alphanumeric: "Alphanumeric",
    /// Make, the code: its memory. `{}`: the memory.
    aqrv_code_step: "Memory {}",
    /// Make, the code: the label of its bytes in hex.
    aqrv_code_bytes: "Bytes",
    /// The button that saves the code as a picture.
    aqrv_save_picture: "Save picture",
    /// The button that saves the code as a .aqrv file.
    aqrv_save_file: "Save .aqrv",
    /// The button that shows the working.
    aqrv_show_working: "Show the working",
    /// The button that makes another code.
    aqrv_make_again: "Make another",
    /// Make: the memory could not be had.
    aqrv_not_enough_memory: "Not enough memory",
    /// Make: the item or passphrase was refused.
    aqrv_not_made: "The code was not made",
    /// Open: the path field's label.
    aqrv_open_path: "File path",
    /// Open: the button that reads the file at the path.
    aqrv_open_file: "Open a file",
    /// Open: the words field's label.
    aqrv_open_words: "Words",
    /// Open: the button that reads the typed or pasted words.
    aqrv_read_words: "Read words",
    /// Open: the button that puts the clipboard's text in the field.
    aqrv_paste: "Paste",
    /// Open: the clipboard had no text.
    aqrv_nothing_to_paste: "Nothing to paste",
    /// Open: how many words were read. `{}`: the number.
    aqrv_words_read: "{} words read",
    /// Open: a word filled or changed. `{}`: its number, what was typed,
    /// the word put there.
    aqrv_word_filled: "Word {}: {} filled with {}",
    /// See `aqrv_word_filled`.
    aqrv_word_changed: "Word {}: {} changed to {}",
    /// Open: corrections were made.
    aqrv_compare_sheet: "Compare these words with the sheet",
    /// Open: the words fail their check, so no passphrase is asked for.
    aqrv_words_do_not_check: "The words do not check",
    /// Open: not a number of words a code has. `{}`: the number read.
    aqrv_words_count: "{} words read; a code has 36, 48 or 56",
    /// Open: words that check but that no writer makes.
    aqrv_not_aqrv_words: "Not Argon QR Vault words",
    /// Open: words run together read more than one way.
    aqrv_words_ambiguous: "The words read more than one way; separate them with spaces",
    /// Open: the file is being read.
    aqrv_reading: "Reading the file",
    /// Open: the file could not be read.
    aqrv_file_unread: "The file could not be read",
    /// Open: the file is not a code, so no passphrase is asked for.
    aqrv_not_a_code: "Not an Argon QR Vault code",
    /// Open: the button that opens the code with the passphrase.
    aqrv_unlock: "Open code",
    /// Open: the code is being opened, with its memory.
    aqrv_opening: "Opening with {}",
    /// Open: neither the tag nor the item's layout holds.
    aqrv_does_not_open: "Does not open: a wrong passphrase or a damaged code",
    /// Open: the button that starts again with no file.
    aqrv_open_another: "Open another",
    /// Open: the item's BIP-39 words.
    aqrv_item_words: "Words",
    /// Open: the item's master fingerprint.
    aqrv_item_fingerprint: "Fingerprint",
    /// Open: a codex32 string.
    aqrv_item_string: "String",
    /// Open: a codex32 string's threshold.
    aqrv_item_threshold: "Threshold",
    /// Open: a codex32 string's identifier.
    aqrv_item_identifier: "Identifier",
    /// Open: a codex32 string's share index.
    aqrv_item_index: "Index",
    /// Open: a codex32 string is a secret.
    aqrv_item_secret: "Secret",
    /// Open: a codex32 string is a share.
    aqrv_item_share: "Share",
    /// Open: a passphrase's or note's text.
    aqrv_item_text: "Text",
    /// Open: a raw key as hex.
    aqrv_item_key: "Key (hex)",
    /// A file was saved, by its name.
    aqrv_saved: "Saved {}",
    /// A file was not saved.
    aqrv_not_saved: "Not saved",
    /// The label of a dialog's closing button.
    aqrv_close: "Close",
    /// The working's dialog title.
    aqrv_working_title: "The working",
    /// The working is being worked out.
    aqrv_working_wait: "Working out the values",
    /// The working: the passphrase's bytes.
    aqrv_w_pw: "Passphrase bytes (NFC)",
    /// The working: Argon2id's output.
    aqrv_w_prk: "Argon2id output",
    /// The working: the encryption key.
    aqrv_w_k_enc: "Encryption key",
    /// The working: the MAC key.
    aqrv_w_k_mac: "MAC key",
    /// The working: the keystream.
    aqrv_w_keystream: "Keystream",
    /// The working: the decrypted item bytes.
    aqrv_w_p: "P",
    /// The working: the encrypted item bytes.
    aqrv_w_c: "C",
    /// The working: the HMAC's message.
    aqrv_w_message: "Tag message",
    /// The working: a kind's tag, by the kind's byte in hex.
    aqrv_w_tag: "Tag, kind {}",
    /// The button that shows About.
    aqrv_about: "About",
    /// About's dialog title.
    aqrv_about_title: "About Argon QR Vault",
    /// The Argon QR Vault's window title and the name its `.exe` carries.
    aqrv_window_title: "Argon QR Vault",
    /// About's text.
    aqrv_about_text: "The format and its test vectors are at github.com/bitcoinpasada/aqrv. The format is not reviewed and is for testing only.",
    /// The publisher in the Windows programs' version block.
    aqrv_publisher: "Argon QR Vault",
}
