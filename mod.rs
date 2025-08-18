use core::ffi::*;
use core::cmp;

use crate::targets::TargetAPI;
use crate::nob::*;
use crate::ir::*;
use crate::arena;
use crate::arena::Arena;
use crate::crust::libc::*;
use crate::missingf;
use crate::lexer::Loc;
use crate::time::Instant;

#[derive(Clone, Copy)]
struct Context {
    sb: String_Builder,
    cmd: Cmd,
    intrns: Array<*const c_char>,
    extrns: Array<*const c_char>,
}

pub unsafe fn get_apis(targets: *mut Array<TargetAPI>) {
    da_append(targets, TargetAPI::V1 {
        name: c!("msvc-x86_64-windows"),
        file_ext: c!(".exe"),
        new,
        build,
        run,
    });
}

pub unsafe fn new(a: *mut Arena, _args: *const [*const c_char]) -> Option<*mut c_void> {
    let ctx = arena::alloc_type::<Context>(a);
    Some(ctx as _)
}

pub unsafe fn build(ctx: *mut c_void, program: *const Program, program_path: *const c_char, garbage_base: *const c_char, _nostdlib: bool, _debug: bool) -> Option<()> {
    let checkpoint = Instant::now();

    let ctx = ctx as *mut Context;
    let output = &mut (*ctx).sb;

    (*ctx).intrns.count = 0;
    (*ctx).extrns.count = 0;

    for i in 0..(*program).funcs.count {
        let func = *(*program).funcs.items.add(i);
        da_append(&mut (*ctx).intrns, func.name);
    }

    for i in 0..(*program).asm_funcs.count {
        let asm_func = *(*program).asm_funcs.items.add(i);
        da_append(&mut (*ctx).intrns, asm_func.name);
    }

    for i in 0..(*program).globals.count {
        let global = *(*program).globals.items.add(i);
        da_append(&mut (*ctx).intrns, global.name);
    }

    'extrns: for i in 0..(*program).extrns.count {
        let extrn = *(*program).extrns.items.add(i);
        for j in 0..(*ctx).intrns.count {
            let intrn = *(*ctx).intrns.items.add(j);
            if strcmp(extrn, intrn) == 0 {
                continue 'extrns;
            }
        }
        da_append(&mut (*ctx).extrns, extrn);
    }

    sb_appendf(output, c!("includelib libcmt\n"));

    for i in 0..(*ctx).extrns.count {
        let extrn = *(*ctx).extrns.items.add(i);
        sb_appendf(output, c!("alias <?%s> = <%s>\n"), extrn, extrn);
    }

    sb_appendf(output, c!(".code\n"));

    for i in 0..(*program).funcs.count {
        let func = *(*program).funcs.items.add(i);
        sb_appendf(output, c!("?%s proc\n"), func.name);

        let stack_size = round_up(func.auto_vars_count * 8, 16);
        sb_appendf(output, c!("    push rbp\n"));
        sb_appendf(output, c!("    mov rbp, rsp\n"));
        if stack_size > 0 {
            sb_appendf(output, c!("    sub rsp, %zu\n"), stack_size);
        }

        const REGISTERS: *const [*const c_char] = &[c!("rcx"), c!("rdx"), c!("r8"), c!("r9")];

        let reg_params_count = cmp::min(func.params_count, REGISTERS.len());
        for i in 0..reg_params_count {
            let reg = (*REGISTERS)[i];
            let index = i + 1;
            store_reg_to_auto(output, reg, index);
        }
        for i in reg_params_count..func.params_count {
            let reg = c!("rax");
            let index = i + 1;
            sb_appendf(output, c!("    mov %s, qword ptr %zu[rbp]\n"), reg, (i + 2) * 8);
            store_reg_to_auto(output, reg, index);
        }

        for i in 0..func.body.count {
            let op = *func.body.items.add(i);
            match op.opcode {
                Op::Bogus => unreachable!("bogus-amogus"),
                Op::UnaryNot       {result, arg} => {
                    load_arg_to_reg(output, op.loc, arg, c!("rax"));
                    sb_appendf(output, c!("    xor rdx, rdx\n"));
                    sb_appendf(output, c!("    cmp rax, 0\n"));
                    sb_appendf(output, c!("    sete dl\n"));
                    store_reg_to_auto(output, c!("rdx"), result);
                },
                Op::Negate         {result, arg} => {
                    load_arg_to_reg(output, op.loc, arg, c!("rax"));
                    sb_appendf(output, c!("    neg rax\n"));
                    store_reg_to_auto(output, c!("rax"), result);
                },
                Op::Asm            {stmts} => {
                    for i in 0..stmts.count {
                        let stmt = *stmts.items.add(i);
                        sb_appendf(output, c!("    %s\n"), stmt.line);
                    }
                },
                Op::Binop          {binop, index, lhs, rhs} => {
                    load_arg_to_reg(output, op.loc, lhs, c!("rax"));
                    load_arg_to_reg(output, op.loc, rhs, c!("rcx"));

                    macro_rules! emit_binary {
                        ($mnemonic:expr, $source:expr) => {{
                            sb_appendf(output, c!("    %s rax, %s\n"), $mnemonic, $source);
                            store_reg_to_auto(output, c!("rax"), index);
                        }}
                    }

                    macro_rules! emit_compare {
                        ($cc:expr) => {{
                            sb_appendf(output, c!("    xor rdx, rdx\n"));
                            sb_appendf(output, c!("    cmp rax, rcx\n"));
                            sb_appendf(output, c!("    set%s dl\n"), $cc);
                            store_reg_to_auto(output, c!("rdx"), index);
                        }}
                    }

                    match binop {
                        Binop::Plus         => emit_binary!(c!("add"), c!("rcx")),
                        Binop::Minus        => emit_binary!(c!("sub"), c!("rcx")),
                        Binop::Mult         => {
                            sb_appendf(output, c!("    imul rcx\n"));
                            store_reg_to_auto(output, c!("rax"), index);
                        },
                        Binop::Div          => {
                            sb_appendf(output, c!("    cqo\n"));
                            sb_appendf(output, c!("    idiv rcx\n"));
                            store_reg_to_auto(output, c!("rax"), index);
                        },
                        Binop::Mod          => {
                            sb_appendf(output, c!("    cqo\n"));
                            sb_appendf(output, c!("    idiv rcx\n"));
                            store_reg_to_auto(output, c!("rdx"), index);
                        },
                        Binop::Equal        => emit_compare!(c!("e")),
                        Binop::NotEqual     => emit_compare!(c!("ne")),
                        Binop::Less         => emit_compare!(c!("l")),
                        Binop::LessEqual    => emit_compare!(c!("le")),
                        Binop::Greater      => emit_compare!(c!("g")),
                        Binop::GreaterEqual => emit_compare!(c!("ge")),
                        Binop::BitOr        => emit_binary!(c!("or"),  c!("rcx")),
                        Binop::BitAnd       => emit_binary!(c!("and"), c!("rcx")),
                        Binop::BitShl       => emit_binary!(c!("shl"), c!("cl")),
                        Binop::BitShr       => emit_binary!(c!("shr"), c!("cl")),
                    };
                },
                Op::Index          {result, arg, offset} => {
                    load_arg_to_reg(output, op.loc, arg, c!("rax"));
                    load_arg_to_reg(output, op.loc, offset, c!("rcx"));
                    sb_appendf(output, c!("    lea rax, qword ptr [rax + rcx * 8]\n"));
                    store_reg_to_auto(output, c!("rax"), result);
                },
                Op::AutoAssign     {index, arg} => {
                    load_arg_to_reg(output, op.loc, arg, c!("rax"));
                    store_reg_to_auto(output, c!("rax"), index);
                },
                Op::ExternalAssign {name, arg} => {
                    load_arg_to_reg(output, op.loc, arg, c!("rax"));
                    sb_appendf(output, c!("    mov ?%s, rax\n"), name);
                },
                Op::Store          {index, arg} => {
                    load_arg_to_reg(output, op.loc, Arg::AutoVar(index), c!("rax"));
                    load_arg_to_reg(output, op.loc, arg, c!("rcx"));
                    sb_appendf(output, c!("    mov qword ptr [rax], rcx\n"));
                },
                Op::Funcall        {result, fun, args} => {
                    let reg_args_count = cmp::min(args.count, REGISTERS.len());
                    for i in 0..reg_args_count {
                        let arg = *args.items.add(i);
                        let reg = (*REGISTERS)[i];
                        load_arg_to_reg(output, op.loc, arg, reg);
                    }

                    let stack_args_count = args.count - reg_args_count;
                    let stack_args_size = round_up(cmp::max(32, stack_args_count * 8), 16);
                    sb_appendf(output, c!("    sub rsp, %zu\n"), stack_args_size);

                    for i in reg_args_count..args.count {
                        let arg = *args.items.add(i);
                        load_arg_to_reg(output, op.loc, arg, c!("rax"));
                        sb_appendf(output, c!("    mov qword ptr %zu[rsp], rax\n"), i * 8);
                    }

                    match fun {
                        Arg::Bogus          => unreachable!("bogus-amogus"),
                        Arg::AutoVar(_)     => missingf!(op.loc, c!("call AutoVar\n")),
                        Arg::Deref(_)       => missingf!(op.loc, c!("call Deref\n")),
                        Arg::RefAutoVar(_)  => missingf!(op.loc, c!("call RefAutoVar\n")),
                        Arg::RefExternal(_) => missingf!(op.loc, c!("call RefExternal\n")),
                        Arg::External(name) => sb_appendf(output, c!("    call ?%s\n"), name),
                        Arg::Literal(_)     => missingf!(op.loc, c!("call Literal\n")),
                        Arg::DataOffset(_)  => missingf!(op.loc, c!("call DataOffset\n")),
                    };

                    sb_appendf(output, c!("    add rsp, %zu\n"), stack_args_size);
                    store_reg_to_auto(output, c!("rax"), result);
                },
                Op::Label          {label} => {
                    sb_appendf(output, c!("$label%zu:\n"), label);
                },
                Op::JmpLabel       {label} => {
                    sb_appendf(output, c!("    jmp $label%zu\n"), label);
                },
                Op::JmpIfNotLabel  {label, arg} => {
                    load_arg_to_reg(output, op.loc, arg, c!("rax"));
                    sb_appendf(output, c!("    test rax, rax\n"));
                    sb_appendf(output, c!("    jz $label%zu\n"), label);
                },
                Op::Return         {arg} => {
                    if let Some(arg) = arg {
                        load_arg_to_reg(output, op.loc, arg, c!("rax"));
                    }
                    if stack_size > 0 {
                        sb_appendf(output, c!("    add rsp, %zu\n"), stack_size);
                    }
                    sb_appendf(output, c!("    pop rbp\n"));
                    sb_appendf(output, c!("    ret\n"));
                },
            }
        }

        load_arg_to_reg(output, func.name_loc, Arg::Literal(0), c!("rax"));
        if stack_size > 0 {
            sb_appendf(output, c!("    add rsp, %zu\n"), stack_size);
        }
        sb_appendf(output, c!("    pop rbp\n"));
        sb_appendf(output, c!("    ret\n"));

        sb_appendf(output, c!("?%s endp\n"), func.name);
    }

    for i in 0..(*program).asm_funcs.count {
        let asm_func = *(*program).asm_funcs.items.add(i);
        sb_appendf(output, c!("?%s proc\n"), asm_func.name);
        for i in 0..asm_func.body.count {
            let statement = *asm_func.body.items.add(i);
            sb_appendf(output, c!("    %s\n"), statement.line);
        }
        sb_appendf(output, c!("?%s endp\n"), asm_func.name);
    }

    sb_appendf(output, c!(".data\n"));

    for i in 0..(*program).globals.count {
        let global = *(*program).globals.items.add(i);
        sb_appendf(output, c!("?%s "), global.name);
        if global.is_vec {
            sb_appendf(output, c!("dq $ + 16\n"));
        }
        for i in 0..global.values.count {
            if global.is_vec || i > 0 {
                sb_appendf(output, c!("    "));
            }
            sb_appendf(output, c!("dq "));
            let value = *global.values.items.add(i);
            match value {
                ImmediateValue::Name(name)         => sb_appendf(output, c!("?%s"), name),
                ImmediateValue::Literal(value)     => sb_appendf(output, c!("%lld"), value),
                ImmediateValue::DataOffset(offset) => sb_appendf(output, c!("$data + %zu"), offset),
            };
            sb_appendf(output, c!("\n"));
        }
        if global.values.count < global.minimum_size {
            if global.is_vec || global.values.count > 0 {
                sb_appendf(output, c!("    "));
            }
            sb_appendf(output, c!("dq %zu dup(0)\n"), global.minimum_size - global.values.count);
        }
    }

    if (*program).data.count > 0 {
        sb_appendf(output, c!("$data db "));
        for i in 0..(*program).data.count {
            if i > 0 {
                if i % 10 != 0 {
                    sb_appendf(output, c!(", "));
                } else {
                    sb_appendf(output, c!("\n      db "));
                }
            }
            sb_appendf(output, c!("0%02xh"), *(*program).data.items.add(i) as c_uint);
        }
        sb_appendf(output, c!("\n"));
    }

    // Better pray nobody uses "option", "nokeyword", "public", "extern", "proc",
    // or "end" as a function or global variable name. I can't see any way around it.

    for i in 0..(*ctx).intrns.count {
        let intrn = *(*ctx).intrns.items.add(i);
        sb_appendf(output, c!("option nokeyword: <%s>\n"), intrn);
        sb_appendf(output, c!("public %s\n"), intrn);
        sb_appendf(output, c!("%s = ?%s\n"), intrn, intrn);
    }

    for i in 0..(*ctx).extrns.count {
        let extrn = *(*ctx).extrns.items.add(i);
        sb_appendf(output, c!("option nokeyword: <%s>\n"), extrn);
        sb_appendf(output, c!("extern %s:proc\n"), extrn);
    }

    sb_appendf(output, c!("end\n"));

    let assembly_path = temp_sprintf(c!("%s.asm"), garbage_base);
    write_entire_file(assembly_path, output.items as *const c_void, output.count);

    let object_path = temp_sprintf(c!("%s.obj"), garbage_base);
    cmd_append!(
        &mut (*ctx).cmd,
        c!("ml64"),
        c!("/nologo"),
        c!("/quiet"),
        c!("/Fo"), object_path,
        c!("/c"),
        assembly_path,
    );
    if !cmd_run_sync_and_reset(&mut (*ctx).cmd) { return None }

    cmd_append!(
        &mut (*ctx).cmd,
        c!("link"),
        c!("/nologo"),
        object_path,
        temp_sprintf(c!("/out:%s"), program_path),
    );
    if !cmd_run_sync_and_reset(&mut (*ctx).cmd) { return None }

    log(Log_Level::INFO, c!("generated %s in %.3fs"), program_path, checkpoint.elapsed().as_secs_f64());

    Some(())
}

pub unsafe fn run(ctx: *mut c_void, program_path: *const c_char, run_args: *const [*const c_char]) -> Option<()> {
    let ctx = ctx as *mut Context;
    let cmd = &mut (*ctx).cmd;
    cmd_append!(cmd, program_path);
    da_append_many(cmd, run_args);
    if !cmd_run_sync_and_reset(cmd) { return None }
    Some(())
}

unsafe fn load_arg_to_reg(output: *mut String_Builder, loc: Loc, arg: Arg, reg: *const c_char) {
    match arg {
        Arg::Bogus              => unreachable!("bogus-amogus\n"),
        Arg::AutoVar(index)     => sb_appendf(output, c!("    mov %s, qword ptr -%zu[rbp]\n"), reg, index * 8),
        Arg::RefAutoVar(index)  => sb_appendf(output, c!("    lea %s, qword ptr -%zu[rbp]\n"), reg, index * 8),
        Arg::External(name)     => sb_appendf(output, c!("    mov %s, ?%s\n"), reg, name),
        Arg::RefExternal(name)  => sb_appendf(output, c!("    lea %s, ?%s\n"), reg, name),
        Arg::Literal(value)     => sb_appendf(output, c!("    mov %s, %lld\n"), reg, value),
        Arg::DataOffset(offset) => sb_appendf(output, c!("    lea %s, $data + %zu\n"), reg, offset),
        Arg::Deref(index)       => {
            load_arg_to_reg(output, loc, Arg::AutoVar(index), c!("rax"));
            sb_appendf(output, c!("    mov %s, qword ptr [rax]\n"), reg)
        },
    };
}

unsafe fn store_reg_to_auto(output: *mut String_Builder, reg: *const c_char, index: usize) {
    sb_appendf(output, c!("    mov qword ptr -%zu[rbp], %s\n"), index * 8, reg);
}

unsafe fn round_up(value: usize, factor: usize) -> usize {
    let remainder = value % factor;
    if remainder != 0 {
        value + factor - remainder
    } else {
        value
    }
}
