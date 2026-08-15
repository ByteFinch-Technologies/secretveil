// Command secretveil keeps a plaintext secret off disk, so that any AI tool
// can read a project's .env file safely.
package main

import "github.com/ByteFinch-Technologies/secretveil/internal/cli"

func main() { cli.Execute() }
