//! The words form through the app's events: a 12-word seed made at the
//! 37-byte size shows its words and copies them, and Open reads them back
//! from a paste, fills a word marked unreadable, and opens the code.

use aqrv::{Size, Step};
use aqrv_app::state::Field;
use aqrv_app::{Action, ArgonQrVault, OpenStage, Page, Tab};
use faraday_shell_api::{App, Command, EntropyBytes, Event, FileKind, Key};
use faraday_text::Text;

const PASS: &str = "correct horse";

fn type_in(app: &mut ArgonQrVault, text: &str) {
    for c in text.chars() {
        app.event(Event::Key(Key::Char(c)));
    }
}

fn answer_entropy(app: &mut ArgonQrVault) {
    while let Some(command) = app.poll_command() {
        if command == Command::RequestEntropy {
            let bytes = std::array::from_fn(|i| 0x37_u8.wrapping_add(i as u8 * 3));
            app.event(Event::Entropy(EntropyBytes::new(bytes)));
        }
    }
}

/// A sample 12-word seed made at 37 bytes: the app, and the text Copy put
/// on the clipboard.
fn made_as_words() -> (ArgonQrVault, String) {
    let mut app = ArgonQrVault::new(|| {});
    app.tap(Action::Sample(0));
    app.tap(Action::Next);
    app.tap(Action::Step(Step::Mib64));
    for field in [Field::Pass, Field::Again] {
        app.tap(Action::Field(field));
        type_in(&mut app, PASS);
    }
    app.tap(Action::Size(Size::Words));
    assert_eq!(app.state().size, Size::Words);
    app.tap(Action::Make);
    answer_entropy(&mut app);
    app.finish_work();
    assert_eq!(app.state().page, Page::Code);
    let made = app.state().made.as_ref().expect("a code was made");
    assert_eq!(made.bytes.len(), 37);
    assert!(made.matrix.is_none() && made.png.is_none());
    assert_eq!(made.words.len(), 36);
    let first = made.words[0];
    app.tap(Action::CopyWords);
    let mut copied = None;
    while let Some(command) = app.poll_command() {
        if let Command::WriteClipboard { text, .. } = command {
            copied = Some(text.to_string());
        }
    }
    let copied = copied.expect("Copy writes the clipboard");
    assert_eq!(copied.lines().count(), 9);
    assert!(copied.starts_with(&format!("1. {first}")));
    (app, copied)
}

fn paste(app: &mut ArgonQrVault, text: &str) {
    app.tap(Action::Tab(Tab::Open));
    app.tap(Action::Field(Field::Words));
    app.tap(Action::Paste);
    let asked = std::iter::from_fn(|| app.poll_command())
        .any(|c| matches!(c, Command::RequestClipboard { .. }));
    assert!(asked);
    app.event(Event::Clipboard {
        kind: FileKind::Any,
        text: Text::of(text),
    });
}

#[test]
fn copied_words_paste_back_and_open() {
    let (mut app, copied) = made_as_words();
    paste(&mut app, &copied);
    app.tap(Action::ReadWords);
    assert_eq!(app.state().open.stage, OpenStage::Asking);
    let read = app.state().open.read.as_ref().expect("words read");
    assert_eq!(read.words.len(), 36);
    assert!(read.corrected.is_empty());
    type_in(&mut app, PASS);
    app.tap(Action::Unlock);
    app.finish_work();
    assert_eq!(app.state().open.stage, OpenStage::Opened);
}

#[test]
fn a_word_marked_unreadable_is_filled_and_shown_before_the_passphrase() {
    let (mut app, _) = made_as_words();
    let mut words: Vec<&str> = app.state().made.as_ref().unwrap().words.clone();
    let want = words[4];
    words[4] = "?";
    let text = words.join(" ");
    paste(&mut app, &text);
    app.event(Event::Key(Key::Enter));
    assert_eq!(app.state().open.stage, OpenStage::Asking);
    let read = app.state().open.read.as_ref().unwrap();
    assert_eq!(read.unreadable, [5]);
    assert_eq!(read.corrected[0].word, want);
}

#[test]
fn words_that_are_not_a_code_ask_for_no_passphrase() {
    let (mut app, _) = made_as_words();
    paste(&mut app, "academic acid acoustic");
    app.tap(Action::ReadWords);
    assert_eq!(app.state().open.stage, OpenStage::NotWords);
    assert!(app.state().open.envelope.is_none());
}
