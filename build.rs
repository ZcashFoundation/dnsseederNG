use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[rustfmt::skip]
    EmitBuilder::builder()
        .all_build()
        .all_git()
        .emit()?; // Emit build instructions
    Ok(())
}
