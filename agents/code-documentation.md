# Documentation
- Comment your code and explain your reasoning in a concise way. Your comments explain why you write that code, not what the code does.
- Never give a number to documented steps.
This is bad as is includes step numbering and only explains what is done, not why:
```
// 1. Create the keypairs
...
// 2. Sign with the keypair
...
// 3. Check the signature
...
```
- Never include line numbers or line counts in documentation
- Reference files by path only, not with specific line numbers
- Always use sentence case in headings
- Add doc comments (`///`) for public APIs
- Use module-level comments (`//!`) for crate documentation
- Include examples in doc comments where helpful
- Document error conditions and panics
