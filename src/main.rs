mod app;
mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    app::run_cli()
}
