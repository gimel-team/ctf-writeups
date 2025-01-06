# Crispy Kelp

**Challenge**: *From [IrisCTF 2025](https://ctftime.org/event/2503) in the “Reverse Engineering” category, tagged as “medium”.*

## tl;dr;

* It’s a Go binary that asks for two inputs: "kelp" and "secure note".
* It generates a random key and encodes the note by XOR + "kelp" (twice). 
* The key as well as both encoded results are hex stored in kelpfile.
* We recovered the key and used it to decrypt the flag.

## Challenge Description

> If you like potato chips, fried kelp might be a good healthy alternative!

We’re given an archive containing binaries `main` and `main.exe`, and a textfile `kelpfile`. Binary `main`, when run, prompts to `Enter your kelp: ` and `Enter secure note: `, and after providing some values, exits.

### Initial Analysis

The text file `kelpfile` that's also in the archive contains a long hexadecimal string:

```
ebb398ebb58cebb594ebb389ebb3a4ebb4b1ebb693ebb2b4ebb58febb38debb5a3ebb59cebb3a2ebb682ebb68eebb39debb485ebb3b3ebb488ebb480ebb2acebb580ebb39febb58debb59cebb5b5ebb4abebb3a4ebb6a2ebb5bfebb69aebb48cebb5b2ebb486ebb3b7ebb5b6ebb4b1ebb58febb6a4ebb587ebb48aebb583ebb382ebb59aebb385ebb395ebb384ebb2acebb2a6f097a4a9f097a8bef097a8b9f097a4bff097a59ff097a9b4f097a6bef097a5a7f097a8b3f097a5bff097a998f097a980f097a4a7f097a895f097a6bbf097a59bf097a894f097a687f097a6a8f097a88ff097a584f097a99cf097a4b8f097a8a8f097a8b9f097aa8bf097aa82f097a68ff097a794f097a9b0f097a880f097a6aff097a8b3f097a6b1f097a4bbf097a9aef097a8b3f097a99ff097a7a2f097a9bcf097a782f097a8a7f097a5a3f097a8acf097a691f097a4b0f097a695f097a5bd
```

Another observation about the file is that it gets overwritten after running the binary. For example, after providing kelp `5` and secure note `abc`, we get the following text in the `kelpfile`:

```
40c395c3a2051f6c61
```

Interestingly, after providing the same values again, we get a slightly different string (that's not even the same length as before):

```
12184a05c2836e71
```

Additionally, when `0` is provided as the `kelp` value, half of the string just seems to be our secure note encoded as ASCII displayed in hexadecimal:

```
c28e1754c387006e616263
```
(`616263` is `abc`)

From the above output, we have another observation: `kelp` is most likely encoded as the character more-or-less in the middle — we can see `05` and `00` in the above examples:

> 40c395c3a2**05**1f6c61 \
> 12184a**05**c2836e71 \
> c28e1754c387**00**6e616263

## Binary Decompilation

Let’s open `main` in [Binary Ninja](https://binary.ninja/) to see what it’s up to. We are greeted with symbols like `runtime.main`, `runtime.gopanic`, and many others, so we know it's a Go binary. The decompiled `main.main()` function looks roughly like this:

```c
int64_t main.main(int64_t arg1, int64_t arg2, void* arg3 @ r14)

{
    void* var_98;
    
    if (&var_98 <= *(uint64_t*)((char*)arg3 + 0x10))
    {
        runtime.morestack_noctxt.abi0(arg1, arg2);
        /* no return */
    }
    
    int64_t zmm15;
    int64_t var_10 = zmm15;
    char var_e9 = 0;
    void* rax = runtime.newobject(&data_4a9fe0, arg3);
    void* rax_1 = runtime.newobject(&data_4a9da0, arg3);
    *(uint64_t*)rax_1 = 0;
    void* const var_30 = &data_4a9da0;
    char const (** const var_28)[0xe4] = &data_4e9760;
    os.Stdout;
    int64_t rdx = fmt.Fprint(1, 1, &data_4e9760, &var_30, &go:itab.*os.File,io.Writer, arg3);
    void* const var_40 = &data_4a7220;
    void* var_38 = rax;
    fmt.Fscanln(1, 1, rdx, &var_40, os.Stdin, arg3);
    void* const var_50 = &data_4a9da0;
    char const (** const var_48)[0xdf] = &data_4e9770;
    os.Stdout;
    int64_t rdx_1 = fmt.Fprint(1, 1, &data_4e9770, &var_50, &go:itab.*os.File,io.Writer, arg3);
    void* const var_60 = &data_4a6fe0;
    void* var_58 = rax_1;
    int64_t rsi;
    int64_t rdi;
    rsi = fmt.Fscanln(1, 1, rdx_1, &var_60, os.Stdin, arg3);
    void* rax_5;
    void* rcx_8;
    int64_t rdx_3;
    int64_t rsi_1;
    int64_t rdi_1;
    int128_t zmm15_1;
    rax_5 = main.encodeString(rdi, rsi, rax_1, *(uint64_t*)rax, *(uint64_t*)rax_1, *(uint64_t*)((char*)rax_1 + 8), arg3);
    
    if (!rcx_8)
    {
        void* rax_7;
        int64_t rcx_10;
        int64_t rdx_4;
        int64_t rsi_2;
        int64_t rdi_2;
        int128_t zmm15_2;
        rax_7 = os.OpenFile(0x1a4, rsi_1, rdx_3, 0x242, "kelpfileGoString01234567beEfFgGv…", 8, arg3);
        int128_t var_90 = zmm15_2;
        var_90 = *(uint64_t*)0x10;
        *(uint64_t*)((char*)var_90)[8] = rcx_10;
        os.Stdout;
        return fmt.Fprintln(1, 1, rdx_4, &var_90, &go:itab.*os.File,io.Writer, arg3);
    }
    
    int128_t var_80 = zmm15_1;
    int128_t var_70 = zmm15_1;
    var_80 = &data_4a9da0;
    *(uint64_t*)((char*)var_80)[8] = &data_4e9780;
    
    if (rcx_8)
        rcx_8 = *(uint64_t*)((char*)rcx_8 + 8);
    
    var_70 = rcx_8;
    *(uint64_t*)((char*)var_70)[8] = rdi_1;
    os.Stdout;
    return fmt.Fprintln(2, 2, &data_4e9780, &var_80, &go:itab.*os.File,io.Writer, arg3);
}
```

We can quickly spot a suspiciously looking function `main.encodeString`. The rest of the code just seems to read data from stdin, and then write data to a file `kelpfile`. Let’s look at the `encodeString` function. This one is quite a bit longer, so let's look at it one step at a time.

```c
void* main.encodeString(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5 @ rax, uint64_t arg6 @ rbx, 
  void* arg7 @ r14)

{
    void var_d8;
    
    if (&var_d8 <= *(uint64_t*)((char*)arg7 + 0x10))
    {
        arg_8 = arg5;
        arg_10 = arg6;
        arg_18 = arg4;
        runtime.morestack_noctxt.abi0(arg1, arg2);
        /* no return */
    }
    
    arg_8 = arg5;
    void var_f8;
    int64_t rax_1 = runtime.stringtoslicerune(arg1, arg6, arg5, arg6, &var_f8, arg5, arg7);
```

Here, Golang seems to be doing some internal checks (not very interesting) and we see a call to `runtime.stringtoslicerune`, so we're converting a UTF-8 encoded string to a slice (array) of Unicode codepoints.

```c
    void* rax_3;
    int64_t rdx_1;
    int64_t rsi_1;
    void* rdi;
    int128_t zmm15;
    rax_3 = main.generateKey(arg5, arg7);
```

Here we're generating some kind of key, judging by the function's name. Quick sneak peek at the functions reveals there's a call to `crypto/rand.Read` inside, so it probably returns a random integer or a slice of random integers.

```c
    if (rdi)
    {
        int128_t var_28 = zmm15;
        
        if (rdi)
            rdi = *(uint64_t*)((char*)rdi + 8);
        
        var_28 = rdi;
        *(uint64_t*)((char*)var_28)[8] = rsi_1;
        fmt.Errorf(1, 1, rdx_1, &var_28, "error encoding string: %vno hex …", 0x19, arg7);
        return 0;
    }
    
    void* rax_4 = runtime.makeslice(rdi, rsi_1, rdx_1, arg5, &data_4a9ee0, arg5, arg7);
    
    for (int64_t i = 0; arg5 > i; i += 1)
    {
        if (arg5 <= i)
        {
            runtime.panicIndex(rax_3, arg5, arg4, arg5);
            /* no return */
        }
        
        *(uint32_t*)((char*)rax_4 + (i << 2)) = (*(uint32_t*)(rax_1 + (i << 2)) ^ *(uint32_t*)((char*)rax_3 + (i << 2))) + arg4;
    }
```

Some error checking, creating a slice and putting some elements inside. Specifically, this code can be rewritten as such:

```c
uint32_t *out;
for (int64_t i = 0; i < arg5; ++i) {
    out[i] = (rax_1[i] ^ rax_3[i]) + arg4;
}
```

We might remember from the previous code snippets that `rax_1` is the name of the slice of Unicode codepoints, and `rax_3` is the key (which indeed is a slice). The code above is XORing the Unicode codepoints with the key and adding the value of one of the arguments to the result.

```c
    void* rax_7 = runtime.makeslice(rax_3, arg5, arg4, arg5, &data_4a9ee0, arg5, arg7);
    int64_t rdx_3 = arg4;
    int64_t rsi_3 = arg5;
    void* rdi_3 = rax_4;
    int64_t rcx_6 = arg5;
    
    for (int64_t i_1 = 0; rcx_6 > i_1; i_1 += 1)
    {
        if (rsi_3 <= i_1)
        {
            runtime.panicIndex(rdi_3, rsi_3, rdx_3, rsi_3);
            /* no return */
        }
        
        *(uint32_t*)((char*)rax_7 + (i_1 << 2)) = (*(uint32_t*)((char*)rax_3 + (i_1 << 2)) ^ *(uint32_t*)((char*)rdi_3 + (i_1 << 2))) + rdx_3;
    }
```

Interestingly, this is almost the same code. This time, however, we XOR the results of the previous XOR with the key and add the value of another argument to the result. So, we have two sequences `a` and `b`, such that:

```
a[i] = (input[i] ^ key[i]) + offset
b[i] = (a[i] ^ key[i]) + offset
```

Let's see what's happening next:

```
    void* var_18 = rax_7;
    void* rbx_4 = rsi_3 + 1;
    
    if (rsi_3 < rbx_4)
    {
        void* rax_9;
        int64_t rcx_8;
        rax_9 = runtime.growslice(1, &data_4a9ee0, rdx_3, rsi_3, rdi_3, rbx_4, arg7);
        rdx_3 = arg4;
        rsi_3 = rcx_8;
        rdi_3 = rax_9;
        rax_7 = var_18;
        rcx_6 = arg5;
    }
    
    *(uint32_t*)((char*)rdi_3 + (rbx_4 << 2) - 4) = rdx_3;
    int64_t rdx_4 = (char*)rbx_4 + rcx_6;
```

We see a call to `runtime.growslice`, so we're resizing the slice to fit more data if needed. Then, we're adding the value of the `offset` (`arg4`, copied here as `rdx_3`) that was added to the sequences earlier.

```c
    if (rsi_3 < rdx_4)
    {
        void* rax_11;
        int64_t rcx_10;
        rax_11 = runtime.growslice(rcx_6, &data_4a9ee0, rdx_4, rsi_3, rdi_3, rdx_4, arg7);
        rdi_3 = rax_11;
        rsi_3 = rcx_10;
        rax_7 = var_18;
        rcx_6 = arg5;
    }
    
    void* rax_13;
    int64_t rdx_5;
    int64_t rsi_5;
    int64_t rdi_6;
    rax_13 = runtime.slicerunetostring(rsi_3, runtime.memmove(rdi_3, rsi_3, rdx_4, rcx_6 << 2, (char*)rdi_3 + (rbx_4 << 2), rax_7), rdx_4, rdx_4, rdi_3, arg7);
```

Here again we have a `runtime.growslice` on the slice (`rdi_3`) we've just modified to allocate more memory, `runtime.memmove` which seems to copy `rax_7` (the slice we've created at the beginning of the function) to (probably the end of) `rdi_3`, and finally `runtime.slicerunetostring` which converts everything into a UTF-8 encoded string.

Then, at the end of the function we have the following:

```    
    if (!rax_13)
        rax_13 = &internal/godebug.stderr;
    
    int64_t rcx_14 = rdi_3 << 1;
    void* rax_14 = runtime.makeslice(rdi_6, rsi_5, rdx_5, rcx_14, &data_4a9e20, rcx_14, arg7);
    void* rbx_9 = nullptr;
    int64_t* rdi_7 = nullptr;

    while (true)
    {
        if (rdi_3 <= rbx_9)
            return runtime.slicebytetostring(rdi_7, rax_13, rcx_14, rcx_14, 0, rax_14, arg7);
        
        uint32_t r8_3 = (uint32_t)*(uint8_t*)((char*)rbx_9 + rax_13);
        uint32_t r9_7 = r8_3;
        r8_3 u>>= 4;
        
        if (rdi_7 >= rcx_14)
        {
            runtime.panicIndex(rdi_7, rax_13, rcx_14, rcx_14);
            /* no return */
        }
        
        *(uint8_t*)((char*)rax_14 + rdi_7) = (*"0123456789abcdefexpected integer…")[(uint64_t)r8_3];
        
        if (rcx_14 <= (char*)rdi_7 + 1)
            break;
        
        *(uint8_t*)((char*)rdi_7 + rax_14 + 1) = *(uint8_t*)(((uint64_t)r9_7 & 0xf) + "0123456789abcdefexpected integer…");
        rbx_9 += 1;
        rdi_7 += 2;
    }
    
    runtime.panicIndex(rdi_7, rax_13, rcx_14, rcx_14);
    /* no return */
}
```

Which seems to be converting the UTF-8 encoded string into a hexadecimal string.

### Decompiled Code Summary

* We create two sequences `a` and `b` by XORing the input string with a randomly generated key and adding a given offset.
* We then concatenate sequence `a` with `offset` and `b`, giving us the following slice:
  ```
  [ a[0], a[1], ..., a[n-1], | kelp | b[0], b[1], ..., b[n-1] ]
  ```
* The concatenated sequence is converted to a UTF-8 string.
* The UTF-8 string is converted to a hexadecimal string.

We can see that this is exactly what we've observed in the kelpfile. The first part seems to be random even though we provide the same input, then we see the `kelp` number, and then another seemingly random part which stops being random when we set `kelp` to zero. This is because the `kelp` number is XORed with the randomly generated key and offset, and then the result is XORed again with the same key and offset, so if the offset is zero, the result is the same as the input.

## Solution

So, we have the following equation:

$$\text{a}[i] = (\text{input}[i] \oplus \text{key}[i]) + \text{kelp}$$
$$\text{b}[i] = (\text{a}[i] \oplus \text{key}[i]) + \text{kelp}$$


We have $\text{a}$, $\text{b}$, and $\text{kelp}$, and we need to recover $\text{input}$. Therefore, we transform these equations into the following:

$$\text{key}[i] = (\text{b}[i] - \text{kelp}) \oplus \text{a}[i]$$
$$\text{input}[i] = (\text{a}[i] - \text{kelp}) \oplus \text{key}[i]$$

All that's left to do is to implement this and run it on the `kelpfile` that was included in the archive. The following Python script does the job:

```python
f = open('<path-to>/kelpfile', 'r').read()
f = bytearray.fromhex(f).decode()
f = [ord(i) for i in f]

half_len = len(f) // 2
a = f[:half_len]
kelp = f[half_len]
b = f[half_len + 1:]

key = [(b_i - kelp) ^ a_i for b_i, a_i in zip(b, a)]
input = [(a_i - kelp) ^ key_i for a_i, key_i in zip(a, key)]

print(''.join([chr(i) for i in input]))
```

## Final Flag

Running the above code reveals the flag:

```
irisctf{k3lp_1s_4_h34lthy_r3pl4c3m3n7_f0r_ch1p5}
```

## Pitfalls to avoid

I've spent quite a lot of time trying to figure out how the hex data is actually encoded. Since I didn't know that Go stores strings as UTF-8, I was trying to decode the hex data directly as 3 or 4 bytes-long integers, which didn't work. It's important to notice that string-related functions are used in the code, and that we have to decode the actual codepoints from the UTF-8 data.  
