## go-flag

`go-flag` is a [Golang](https://en.wikipedia.org/wiki/Go_(programming_language)) program that implements several [Brainfxxk](https://en.wikipedia.org/wiki/Brainfuck)-like instructions. It starts over 3000 goroutes to check the flag inputted by the user.

To solve the challenge, I use [ptrace](https://www.man7.org/linux/man-pages/man2/ptrace.2.html) to debug the program dynamically and read flags from its register.

flag: `RCTF{my_br4in_is_f__ked}`
