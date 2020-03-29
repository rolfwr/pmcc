// C Library
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

// Posix
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define verify(expr) ((expr) ? (void)(0) : verify_fail(#expr, __FILE__, __LINE__, __func__));

void write_string(int fd, const char* str) {
    size_t len = strlen(str);
    write(fd, str, len);
}

void write_int(int fd, int value) {
    if (value < 0) {
        write_string(fd, "-");
        value = -value;
    }

    if (value > 9) {
        int lead = value / 10;
        value =  value - 10 * lead;
        write_int(fd, lead);
    }

    char c = '0' + (char)value;
    write(fd, &c, 1);
}

void verify_fail(const char* expr, const char* file, int line, const char* function) {
    int err = STDERR_FILENO;
    write_string(err, file);
    write_string(err, ":");
    write_int(err, line);
    write_string(err, ":1: error: ");
    write_string(err, function);
    write_string(err, ": verify expectation '");
    write_string(err, expr);
    write_string(err, "' failed.\n");
    abort();
}

void* xmalloc(size_t bytes) {
    void* allocated = malloc(bytes);
    verify(allocated != 0);
    return allocated;
}

void* xrealloc(void* ptr, size_t new_size) {
    assert(ptr != 0);
    void* reallocated = realloc(ptr, new_size);
    verify(reallocated != 0);
    return reallocated;
}

struct stream {
    int fd;
};

void stream_init_openread(struct stream* s, const char* filepath) {
    memset(s, 0, sizeof(struct stream));
    s->fd = open(filepath, 0);
    verify(s->fd != -1);
}

int stream_read_char(struct stream* s) {
    char c = 0;
    int count = read(s->fd, &c, 1);
    if (!count) {
        return -1;
    }
    int ic = c;
    return ic & 255;
}

void stream_read(struct stream* s, void* buf, ssize_t nbytes) {
    ssize_t nread = read(s->fd, buf, nbytes);
    verify(nread == nbytes);
}

int stream_tell(struct stream* s) {
    off_t filepos = lseek(s->fd, 0, SEEK_CUR);
    verify(filepos != -1);
    return filepos;
}

void stream_seek(struct stream* s, off_t pos) {
    off_t filepos = lseek(s->fd, pos, SEEK_SET);
    verify(filepos != -1);
}

int stream_eof(struct stream* s) {
    off_t pos = stream_tell(s);
    if (stream_read_char(s) == -1) {
        return 1;
    }

    stream_seek(s, pos);
    return 0;
}

void stream_dump_tail(struct stream* s) {
    off_t pos = stream_tell(s);
    int i = 40;
    int ic = 0;
    while (i > 0 && ic != -1) {
        ic = stream_read_char(s);
        if (ic != -1) {
            char c = ic;
            write(STDOUT_FILENO, &c, 1);
        }
        i = i - 1;
    }

    if (!stream_eof(s)) {
        write_string(STDOUT_FILENO, "...");
    }

    write_string(STDOUT_FILENO, "\n");

    stream_seek(s, pos);
}

void dump_not_hint(struct stream* s, const char* what) {
    write_string(STDOUT_FILENO, "Not ");
    write_string(STDOUT_FILENO, what);
    write_string(STDOUT_FILENO, ": ");
    stream_dump_tail(s);
}

void fail_expected(struct stream* s, const char* expected) {
    write_string(STDERR_FILENO, "error: Expected ");
    write_string(STDERR_FILENO, expected);
    write_string(STDERR_FILENO, ", got: ");
    stream_dump_tail(s);
    abort();
}

enum {
    vt_none,
    vt_identifier,
    vt_char_constant
};

struct value {
    int type;

    // One of
    char* identifier;
    char char_constant;
};

void value_init(struct value* val) {
    memset(val, 0, sizeof(struct value));
}


struct buffer {
    char bytes[32];
    int count;
};

void buffer_init(struct buffer* buf) {
    memset(buf, 0, sizeof(struct buffer));
}

int buffer_expand(struct buffer* buf, int count) {
    int index = buf->count;
    buf->count = buf->count + count;
    verify(buf->count <= 32);
    return index;
}

char* buffer_at(struct buffer* buf, int index) {
    return &(buf->bytes[index]);
}

struct constbytetable {
    int indexes[256];
};

void constbytetable_init(struct constbytetable* cbt) {
    int i = 0;
    while (i < 256) {
        cbt->indexes[i] = -1;
        i = i + 1;
    }
}

struct patch {
    // Only data address patches for now.
    int target;
    int offset;
};

struct patchlist {
    int count;
    int reserved;
    struct patch* entries;
};

void patchlist_init(struct patchlist* pl) {
    pl->count = 0;
    pl->reserved = 16;
    pl->entries = (struct patch*)xmalloc(pl->reserved * sizeof(struct patch));
}

void patchlist_push(struct patchlist* pl) {
    assert(pl->count <= pl->reserved);
    if (pl->count == pl->reserved) {
        assert(pl->reserved > 0);
        pl->reserved = pl->reserved * 2;
        pl->entries = (struct patch*)xrealloc(pl->entries, pl->reserved * sizeof(struct patch));
    }

    pl->count = pl->count + 1;
    assert(pl->count <= pl->reserved);
}

struct patch* patchlist_back(struct patchlist* pl) {
    return &(pl->entries[pl->count - 1]);
}

// symbol kinds
enum {
    st_none,
    st_variable,
    st_function
};

enum {
    ts_none,
    ts_undefined,
    ts_char,
    ts_int
};

int typespecifier_sizeof(int typespec) {
    verify(typespec == ts_char);
    return 1;
}

struct symbol {
    char* name;
    int kind;
    int typespec;
    // compilation specific
    int dataoffset;
};

void symbol_init(struct symbol* sym, char* name) {
    sym->name = name;
    sym->kind = st_none;
    sym->typespec = ts_none;
    sym->dataoffset = -1;
}

struct symboltable {
    struct symbol entries[16];
    int count;
};

void symboltable_init(struct symboltable* symtab) {
    memset(symtab, 0, sizeof(struct symboltable));
}

struct symbol* symboltable_find(struct symboltable* symtab, char* name) {
    int i = 0;
    while (i < symtab->count) {
        if (strcmp(name, symtab->entries[i].name) == 0) {
            return &(symtab->entries[i]);
        }

        i = i + 1;
    }
    return 0;
}

struct symbol* symboltable_add(struct symboltable* symtab, char* name) {
    assert(symboltable_find(symtab, name) == 0);
    verify(symtab->count < 16);
    struct symbol* new_entry = &(symtab->entries[symtab->count]);
    symtab->count = symtab->count + 1;
    symbol_init(new_entry, name);
    return new_entry;
}

struct output {
    int fd;
    struct buffer data;
    struct constbytetable constbytes;
    struct patchlist patches;
    struct symboltable symbols;
};

void output_init(struct output* o, int fd) {
    o->fd = fd;
    buffer_init(&(o->data));
    constbytetable_init(&(o->constbytes));
    assert(o->constbytes.indexes[42] == -1);
    patchlist_init(&(o->patches));
    symboltable_init(&(o->symbols));
}

int output_get_const_byte_data_offset(struct output* o, char value) {
    int index = value & 255;
    assert(index >= 0 && index <= 255);

    int data_offset = o->constbytes.indexes[index];
    assert(o->constbytes.indexes[42] == -1);
    if (data_offset == -1) {
        data_offset = buffer_expand(&(o->data), 1);
        *buffer_at(&(o->data), data_offset) = value;
        o->constbytes.indexes[index] = data_offset;
    }

    return data_offset;
}

// The latest freely available draft of ISO/IEC 9899:2018
// https://web.archive.org/web/20181230041359if_/http://www.open-std.org/jtc1/sc22/wg14/www/abq/c17_updated_proposed_fdis.pdf

/*
    Implemented:
        whitespace <- [ \n\r\t]

    Examples (C-like syntax):
        " "
        "\n"
*/
int count_whitespace(struct stream* s) {
    off_t pos = stream_tell(s);
    int ic = stream_read_char(s);
    if (ic == -1) {
        // No match
        return 0;
    }

    char c = ic;
    int is_whitespace = c == ' ' || c == '\n' || c == '\r' || c == '\t';

    if (!is_whitespace) {
        // Rewind and return no match
        stream_seek(s, pos);
        return 0;
    }

    // Match
    return 1;
}
/*
    Spacing <- ( WhiteSpace / LongComment / LineComment / Pragma )*

    Implemented:
        spacing <- whitespace*

    Examples (C-like syntax):
        "    "
        "\t"
        "\r\n"
*/
int count_spacing(struct stream* s) {
    int all = 0;
    int last = -1;
    while (last) {
        last = count_whitespace(s);
        all = all + last;
    }

    return all;
}

/*
    N2176: 6.4.2.1 1 identifier-nondigit:
        identifier-nondigit <- nondigit / universal-character-name / other-implementation-defined-characters
        nondigit <- [a-z] / [A-Z] / [_]

    Implemented:
        id_nondigit <- [a-z] / [A-Z] / [_]

    Examples:
        r
        W
        _
*/
int match_id_nondigit(struct stream* s) {
    off_t pos = stream_tell(s);
    int ic = stream_read_char(s);
    if (ic == -1) {
        return 0;
    }

    char c = ic;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
        return 1;
    }

    stream_seek(s, pos);
    return 0;
}

/*
    IdChar <- [a-z] / [A-Z] / [0-9] / [_] / UniversalCharacter

    Implemented:
        id_char <- id_nondigit / [0-9]

    Examples:
        4
        r
        _
*/
int match_id_char(struct stream* s) {
    if (match_id_nondigit(s)) {
        return 1;
    }

    off_t pos = stream_tell(s);
    int ic = stream_read_char(s);
    if (ic == -1) {
        return 0;
    }

    char c = ic;
    if (c >= '0' && c <= '9') {
        return 1;
    }

    stream_seek(s, pos);
    return 0;
}
/*
    Examples (expected = "str"):
        str
*/
int match_string(struct stream* s, const char* expected) {
    off_t pos = stream_tell(s);
    while (*expected) {
        int ic = stream_read_char(s);
        char c = ic;
        if (ic == -1 || c != *expected) {
            // Unexpected EOF or char mismatch
            stream_seek(s, pos);
            return 0;
        }

        ++expected;
    }

    return 1;
}

/*
    Examples (C-like syntax, expected = "str"):
        "str\r\n"
        "str    "
*/
int match_string_with_spacing(struct stream* s, const char* expected) {
    if (!match_string(s, expected)) {
        return 0;
    }

    count_spacing(s);

    return 1;
}

/*
    Examples (partial match, expected = "exam"):
        exam + ple
        ^^^^^ MATCH

        examp + le
        NO MATCH
*/
int match_word(struct stream* s, const char* expected) {
    off_t pos = stream_tell(s);

    if (!match_string(s, expected)) {
        return 0;
    }

    if (match_id_char(s)) {
        // Unexpected trailing char
        stream_seek(s, pos);
        return 0;
    }

    count_spacing(s);

    return 1;
}



/*
    N2176: 6.7.2 1 type-specifier
        type-specifier <-
            VOID / CHAR / SHORT / INT / LONG / FLOAT / DOUBLE / SIGNED / UNSIGNED /
            BOOL / COMPLEX / atomic-type-specifier / struct-or-union-specifier / enum-specifier / typedef-name

    Implemented:
        type_specifier <- CHAR / INT
        CHAR <- 'char' !id_char spacing
        INT <- 'char' !id_char spacing

    Examples (C-like syntax):
        "char "
        "int\r\n"
*/
int match_type_specifier(struct stream* s) {
    if (match_word(s, "char")) {
        return ts_char;
    }

    if (match_word(s, "int")) {
        return ts_int;
    }

    assert(!ts_none);
    return ts_none;
}

/*
    N2176: 6.7 1 declaration-specifiers
        declaration-specifiers <-
            storage-class-specifier declaration-specifiers? /
            type-specifier declaration-specifiers? /
            type-qualifier declaration-specifiers? /
            function-specifier declaration-specifiers? /
            alignment-specifier declaration-specifiers?

    Implemented:
        declaration_specifiers <- type_specifier

    Examples (C-like syntax):
        "char "
        "int\r\n"
*/
int match_declaration_specifiers(struct stream* s) {
    return match_type_specifier(s);
}

/*
    N2176: 6.4.2.1 identifier:
        identifier <- identifier-nondigit / identifier identifier-nondigit/ identifier digit

    Implemented:
        identifier <- id_nondigit id_char* spacing

    Examples:
        Hello
        n7
        _
*/
char* read_identifier(struct stream* s) {
    off_t pos = stream_tell(s);
    if (!match_id_nondigit(s)) {
        return 0;
    }

    while (match_id_char(s)) {
        // continue
    }

    off_t len = stream_tell(s) - pos;
    stream_seek(s, pos);

    // Read as null terminated string.
    char* id = (char*)malloc(len + 1);
    stream_read(s, id, len);
    id[len] = 0;

    count_spacing(s);

    return id;
}

/*
    N2176: 6.7.6 direct-declarator:
        direct-declarator <-
            identifier
            / LPAR Declarator RPAR
            / LBRK type-qualifier-list? assignment-expression? RBRK
            / LBRK STATIC type-qualifier-list? assignment-expression RBRK
            / LBRK STATIC type-qualifier-list? STAR RBRK
            / LPAR parameter-type-list RPAR
            / LPAR identifier-list? RPAR

    Implemented:
        direct_declarator <- identifier (LPAR (RPAR / fail))?
        LPAR <-  '(' spacing
        RPAR <-  ')' spacing

    Examples:
        main()
        main ( )
        byte_count
        lf
*/
int read_direct_declarator(struct stream* s, struct symbol* decl_out) {
    char* name = read_identifier(s);
    if (!name) {
        return 0;
    }

    decl_out->name = name;

    off_t pos = stream_tell(s);

    if (!match_string_with_spacing(s, "(")) {
        stream_seek(s, pos);
        decl_out->kind = st_variable;
        return 1;
    }

    if (!match_string_with_spacing(s, ")")) {
        fail_expected(s, "')'");

        stream_seek(s, pos);
        decl_out->kind = st_variable;
        return 1;
    }

    decl_out->kind = st_function;
    return 1;
}

/*
    N2176: 6.7.6 declarator:
        delarator <- pointer? direct-declarator

    Implemented:
        declarator <- direct_declarator

    Examples:
        main()
        main ( )
        byte_count
        lf
*/
int read_declarator(struct stream* s, struct symbol* decl_out) {
    return read_direct_declarator(s, decl_out);
}

/*
    N2176: 6.4.4.4 simple-escape-sequence:
        simple-escape-sequence <-
            '\\\''
            / '\\"'
            / '\\?'
            / '\\\\'
            / '\\a'
            / '\\b'
            / '\\f'
            / '\\n'
            / '\\r'
            / '\\t'
            / '\\v'

    Implemented:
        simple_escape <- '\\' ['\\"?abdnrtv]

    Examples:
        \\
        \"
        \r
        \n
*/
int read_simple_escape(struct stream* s) {
    int pos = stream_tell(s);
    if (!match_string(s, "\\")) {
        return -1;
    }

    int ic = stream_read_char(s);
    if (ic != -1) {
        char c = ic;
        if (c == '\'' || c == '\\' || c == '"' || c == '?') {
            return ic;
        }

        if (c == 'a') {
            return '\a';
        }

        if (c == 'b') {
            return '\b';
        }

        if (c == 'f') {
            return '\f';
        }

        if (c == 'n') {
            return '\n';
        }

        if (c == 'r') {
            return '\r';
        }

        if (c == 't') {
            return '\t';
        }

        if (c == 'v') {
            return '\t';
        }
    }

    stream_seek(s, pos);
    return -1;
}

/*
    N2176: 6.4.4.4 escape-sequence:
        escape-sequence <- simple-escape-sequence / octal-escape-sequence / hexidecimal_escape_sequence / universal-character-name

    Implemented:
        escape <- simple_escape

    Examples:
        \\
        \"
        \r
        \n
*/
int read_escape(struct stream* s) {
    return read_simple_escape(s);
}

/*
    N2176: 6.4.4.4 c-char:
        c-char <-
            any-member-of-the-source-character-set-except-the-single-quote-backslash-or-newline-character
            / escape-sequence

    Implemented:
        char <- escape / !['\n\\] .

    Examples:
        r
        "
        \\
        \n
*/
int read_char(struct stream* s) {
    off_t pos = stream_tell(s);

    int ic = read_simple_escape(s);
    if (ic != -1) {
        return ic;
    }

    ic = stream_read_char(s);

    if (ic == -1) {
        return -1;
    }

    char c = ic;
    if (c == '\'' || c == '\n' || c == '\\') {
        stream_seek(s, pos);
        return -1;
    }

    return ic;
}

/*
    N2176: 6.4.4.4 character-constant:
        character-constant <-
            ['] c-char-sequence [']
            / 'L' ['] c-char-sequence [']
            / 'u' ['] c-char-sequence [']
            / 'U' ['] c-char-sequence [']

    Implemented:
        character_constant <- ['] char [']

    Examples:
        'r'
        '"'
        '\\'
        '\n'
*/
int read_character_constant(struct stream* s) {
    off_t pos = stream_tell(s);
    if (!match_string(s, "'")) {
        return -1;
    }

    int ic = read_char(s);
    if (ic == -1) {
        stream_seek(s, pos);
        return -1;
    }

    if (!match_string(s, "'")) {
        stream_seek(s, pos);
        return -1;
    }

    count_spacing(s);
    return ic;
}

/*
    N2176: 6.4.4 constant:
        constant <- integer-constant / floating-constant / enumeration-constant / character-constant

    Implemented:
        constant <- character_constant

    Examples:
        'r'
        '"'
        '\\'
        '\n'
*/
int match_constant(struct stream* s, struct value* val_out) {
    int charconst = read_character_constant(s);

    if (charconst == -1) {
        return 0;
    }

    val_out->type = vt_char_constant;
    val_out->char_constant = charconst;
    return 1;
}

struct list {
    struct value values[16];
    int count;
};

void list_init(struct list* l) {
    memset(l, 0, sizeof(struct list));
}

struct value* list_back(struct list* l) {
    verify(l->count > 0);
    return &l->values[l->count - 1];
}

void list_push(struct list* l) {
    l->count = l->count + 1;
    verify(l->count <= 16);
    value_init(list_back(l));
}

void list_pop(struct list* l) {
    verify(l->count > 0);
    l->count = l->count - 1;
}

/*
    N2176: 6.5.1 1 primary-expression:
        primary-expression <- identifier / constant / string-literal / LPAR expression RPAR / generic-selection

    Implemented:
        primary_expression <- identifier / constant

    Examples:
        main
        error_code
        'r'
        '\n'
*/
int match_primary_expression(struct stream* s, struct value* out_val) {
    char* id = read_identifier(s);
    if (id) {
        out_val->type = vt_identifier;
        out_val->identifier = id;
        return 1;
    }

    if (match_constant(s, out_val)) {
        return 1;
    }

    return 0;
}

int process_argument_expression_list(struct stream* s, struct list* args_out, struct output* prog_out);

void output_emit_byte(struct output* prog_out, char byte) {
    int wrote = write(prog_out->fd, &byte, 1);
    verify(wrote == 1);
}

void output_emit_data_pointer(struct output* prog_out, int data_offset) {
    int placeholder_pos = lseek(prog_out->fd, 0, SEEK_CUR);
    verify(placeholder_pos != -1);

    // write data pointer:
    int i = 0;
    while (i < 4) {
        output_emit_byte(prog_out, 0);
        i = i + 1;
    }

    patchlist_push(&prog_out->patches);
    struct patch* addrpatch = patchlist_back(&prog_out->patches);
    addrpatch->offset = data_offset;
    addrpatch->target = placeholder_pos;
}

/*
    N2176: 6.5.2 postfix-expression:
        postfix-expression <-
            primary-expression
            / postfix-expression LBRK expression RBRK
            / postfix-expression LPAR argument-expression-list? RPAR
            / postfix-expression DOT identifier
            / postfix-expression PTR identifier
            / postfix-expression INC
            / postfix-expression DEC
            / LPAR type-name RPAR LWING initializer-list RWING
            / LPAR type-name RPAR LWING initializer-list COMMA RWING

    Implemented:
        postfix_expression <- primary_expression (LPAR argument_expression_list? (RPAR / fail))?
        LPAR <- '(' spacing
        RPAR <- ')' spacing

    Examples:
        error_code
        'H'
        putchar('H')
        abort()

    Examples (ok grammar, semantic error):
        'H'()
        ^^^^^ ERROR: called primary expression is not a function nor a function pointer
*/
int process_postfix_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    assert(val_out->type == vt_none);

    if (!match_primary_expression(s, val_out)) {
        return 0;
    }

    assert(val_out->type != vt_none);

    off_t pos = stream_tell(s);
    if (!match_string_with_spacing(s, "(")) {
        return 1;
    }

    struct list args;
    list_init(&args);

    process_argument_expression_list(s, &args, prog_out);

    if (!match_string_with_spacing(s, ")")) {
        fail_expected(s, "argument expression or ')'");
        stream_seek(s, pos);
        return 1;
    }

    verify(val_out->type == vt_identifier);
    verify(strcmp(val_out->identifier, "putchar") == 0);

    verify(args.count == 1);
    struct value* chararg = list_back(&args);
    int data_offset;
    if (chararg->type == vt_char_constant) {
        // Handle specifically:
        //     putchar('?');
        assert(chararg->type == vt_char_constant);
        data_offset = output_get_const_byte_data_offset(prog_out, chararg->char_constant);
    } else {
        // Handle specifically:
        //     putchar(someVariable);
        verify(chararg->type == vt_identifier);

        struct symbol* sym = symboltable_find(&(prog_out->symbols), chararg->identifier);
        assert(strcmp(sym->name, chararg->identifier) == 0);
        verify(sym->kind == st_variable);
        verify(sym->typespec == ts_char);
        verify(sym->dataoffset != -1);
        data_offset = sym -> dataoffset;
    }

    char opcode_out = 1;
    output_emit_byte(prog_out, opcode_out);
    output_emit_data_pointer(prog_out, data_offset);

    // putchar() returns the given argument unless error occurs.
    memcpy(val_out, chararg, sizeof(struct value));
    return 1;
}

/*
    N2176: 6.5.3 unary-expression:
        unary-expresion <-
            postfix-expression
            / INC unary-expression
            / DEC unary-expression
            / unary-operator cast-expression
            / SIZEOF unary-expression
            / SIZEOF LPAR type-name RPAR
            / ALIGNOF LPAR type-name RPAR

    Implemented:
        unary_expression <- postfix_expression

    Examples:
        error_code
        'H'
        putchar('H')
        abort()
*/
int process_unary_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    return process_postfix_expression(s, val_out, prog_out);
}

/*
    N2176: 6.5.15 conditional-expression:
        conditional-expression <-
            logical-OR-expression
            / logical-OR-expression QUERY expression COLON conditional-expression

    Implemented:
        conditional-expression <- unary_expression

    Examples:
        error_code
        'H'
        putchar('H')
        abort()
*/
int process_conditional_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    return process_postfix_expression(s, val_out, prog_out);
}

/*
    Implemented:
        EQU <- '=' !'=' spacing

    Examples (partial match):
        = 42
        ^^ MATCH

        =- 42
        ^ MATCH

        == 42
        NO MATCH
*/
int match_equ(struct stream* s) {
    off_t pos = stream_tell(s);
    if (!match_string(s, "=")) {
        return 0;
    }

    if (match_string(s, "=")) {
        stream_seek(s, pos);
        return 0;
    }

    count_spacing(s);
    return 1;
}

/*
    N2176: 6.5.16: assignement-operator:
        assignment-operator <-
            EQU
            / STAREQU
            / DIVEQU
            / MODEQU
            / PLUSEQU
            / MINUSEQU
            / LEFTEQU
            / RIGHTEQU
            / ANDEQU
            / HATEQU
            / OREQU

    Implemented:
        assignement_operator <- EQU

    Examples:
        =
*/
int match_assignment_operator(struct stream* s) {
    return match_equ(s);
}

void note_processed_as(struct stream* s, off_t pos, const char* what) {
    write_string(STDERR_FILENO, "note: Processed as ");
    write_string(STDERR_FILENO, what);
    write_string(STDERR_FILENO, ": ");

    off_t here = stream_tell(s);
    stream_seek(s, pos);

    int count = here - pos;
    while (count > 0) {
        int ic = stream_read_char(s);
        verify(ic != -1);
        char c = ic;
        int wrote = write(STDERR_FILENO, &c, 1);
        verify(wrote == 1);

        count = count - 1;
    }

    write_string(STDERR_FILENO, "\n");

    assert(stream_tell(s) == here);
}
/*
    N2176: 6.5.16: assignment-expression:
        assignment-expression <- conditional-expression / unary-expression assignment-operator assignment-expression

    Implemented:
        assignment_expression <- conditional-expression (assignment_operator (assignment_expression / fail))?

    Examples:
        error_code
        error_code = 4
        'H'
        putchar('H')

    Examples (ok grammar, semantic error):
        'H' = 4
         ^^^^^^ ERROR: lvalue required as left operand of assignment
*/
int process_assignment_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    if (!process_conditional_expression(s, val_out, prog_out)) {
        return 0;
    }

    off_t pos = stream_tell(s);

    if (match_assignment_operator(s)) {
        struct value aexpr;
        value_init(&aexpr);

        if (!process_assignment_expression(s, &aexpr, prog_out)) {
            note_processed_as(s, pos, "assignment operator");
            fail_expected(s, "assignment expression after assignement operator");
            stream_seek(s, pos);
        }

        // Handle specifically:
        //     someVariableName = '?'

        verify(val_out->type == vt_identifier);

        struct symbol* variable = symboltable_find(&(prog_out->symbols), val_out->identifier);
        verify(variable != 0);
        assert(strcmp(variable->name, val_out->identifier) == 0);

        verify(variable->kind == st_variable);
        verify(variable->typespec == ts_char);

        verify(aexpr.type == vt_char_constant);

        int vardataoffset = variable->dataoffset;
        int opcode_sub = 3;

        int negconstoffset = output_get_const_byte_data_offset(prog_out, (256 - aexpr.char_constant) & 255);

        // sub var var
        // sub var constant((256 - c) & 0xff)

        output_emit_byte(prog_out, opcode_sub);
        output_emit_data_pointer(prog_out, vardataoffset);
        output_emit_data_pointer(prog_out, vardataoffset);

        output_emit_byte(prog_out, opcode_sub);
        output_emit_data_pointer(prog_out, vardataoffset);
        output_emit_data_pointer(prog_out, negconstoffset);

        memcpy(val_out, &aexpr, sizeof(struct value));
    }

    return 1;
}

/*
    N2176: 6.5.2 argument-expression-list:
        argument-expression-list <- assignment-expression / argument-expression-list COMMA assignment-expression

    Implemented:
        argument_expression_list <- assignment-expression (COMMA assignment-expression)*
        COMMA <- ',' spacing

    Examples:
        foo = 'A', bar = 'B'
        'C', main, bar = 'D', baz
        'E'
        putchar('F')
*/
int process_argument_expression_list(struct stream* s, struct list* args_out, struct output* prog_out) {
    struct value val;
    value_init(&val);

    if (!process_assignment_expression(s, &val, prog_out)) {
        return 0;
    }

    list_push(args_out);
    memcpy(list_back(args_out), &val, sizeof(struct value));

    while (1) {
        off_t pos = stream_tell(s);
        if (!match_string_with_spacing(s, ",")) {
            return 1;
        }

        value_init(&val);

        if (!process_assignment_expression(s, &val, prog_out)) {
            stream_seek(s, pos);
            return 1;
        }

        list_push(args_out);
        memcpy(list_back(args_out), &val, sizeof(struct value));
    }
}


/*
    N2176: 6.5.17 expression:
        expression <- assignment-expression / expression COMMA assignment-expression

    Implemented:
        expression <- process_assignment_expression

    Examples:
        error_code
        error_code = 4
        'H'
        putchar('H')
*/
int process_expression(struct stream* s, struct output* prog_out) {
    struct value val;
    value_init(&val);
    return process_assignment_expression(s, &val, prog_out);
}

/*
    N2176: 6.8.3 expression-statement:
        expression-statement <- expression? SEMI

    Implemented:
        expression (SEMI / fail) / SEMI
        SEMI <- ';' spacing

    Examples:
        'H';
        error_code = 4;
        putchar('H');
        ;
*/
int process_expression_statement(struct stream* s, struct output* prog_out) {
    off_t pos = stream_tell(s);
    int saw_expression = process_expression(s, prog_out);
    int saw_semi = match_string_with_spacing(s, ";");
    if (saw_expression && !saw_semi) {
        // Can't unwind processing of expression
        fail_expected(s, "';' after expression");
        stream_seek(s, pos);
        return 0;
    }

    return saw_semi;
}

/*
    N2176: 6.8 statement:
        statement <-
            labeled-statement
            / compound-statement
            / expression-statement
            / selection-statement
            / iterator-statement
            / jump-statement

    Implemented:
        statement <- expression-statement

    Examples:
        'H';
        error_code = 4;
        putchar('H');
        ;
*/

int process_statement(struct stream* s, struct output* prog_out) {
    return process_expression_statement(s, prog_out);
}

/*
    N2176: 6.7 init-declarator:
        init-declarator <- declarator / declarator EQU initializer

    Implemented:
        init-declarator <- declarator

    Examples:
        main()
        main ( )
        byte_count
        lf
*/
int read_init_declarator(struct stream* s, struct symbol* decl_out) {
    return read_declarator(s, decl_out);
}


/*
    N2176: 6.7 init-declarator-list:
        init-declarator-list <- init-declarator / init-declarator-list COMMA init-declarator

    Implemented:
        init-declarator-list <- init_declarator

    Examples:
        main()
        main ( )
        byte_count
        lf
*/
int match_init_declarator_list(struct stream* s, struct symbol* decl_out) {
    return read_init_declarator(s, decl_out);
}


/*
    N2176: 6.7 declaration:
        declaration <- declaration-specifiers init-declarator-list? SEMI / static_assert-declaration

    Implemented:
        declaration <- declaration_specifiers init-declarator-list SEMI

    Examples:
        char getdirsep();
        int main();
        int byte_count;
        char lf;

*/
int process_declaration(struct stream* s, struct output* prog_out) {
    off_t pos = stream_tell(s);

    int typespec = match_declaration_specifiers(s);

    if (!typespec) {
        return 0;
    }

    struct symbol decllist;
    symbol_init(&decllist, 0);

    if (!match_init_declarator_list(s, &decllist)) {
        stream_seek(s, pos);
        return 0;
    }

    if (!match_string_with_spacing(s, ";")) {
        stream_seek(s, pos);
        return 0;
    }

    // Specifically support:
    //     char someVariableName;
    verify(typespec == ts_char);

    verify(symboltable_find(&(prog_out->symbols), decllist.name) == 0);

    struct symbol* newvar = symboltable_add(&(prog_out->symbols), decllist.name);

    assert(newvar != 0);
    assert(strcmp(newvar->name, decllist.name) == 0);
    memcpy(newvar, &decllist, sizeof(struct symbol));

    newvar->typespec = typespec;

    // Make appropriate amount of room for the new variable, and remember where
    // we put it.
    newvar->dataoffset = buffer_expand(&(prog_out->data), typespecifier_sizeof(newvar->typespec));

    assert(symboltable_find(&(prog_out->symbols), decllist.name) == newvar);

    return 1;
}

/*
    N2176: 6.8.2 compound-statement:
        compound-statement <- LWING block-list-item? RWING
        block-list-item <- block-item / block-list-item
        block-item <- declaration / statement

    Implemented:
        compound_statement <- LWING ( Declaration / Statement )* (RWING / fail)
        LWING <- '{' spacing
        RWING <- '}' spacing

    Examples:
        {}
        { putchar('H'); }
        { char foo(); }
        { 'H'; error_code = 4; putchar('H'); ; }
*/
int match_compound_statement(struct stream* s, struct output* prog_out) {
    off_t pos = stream_tell(s);

    if (!match_string_with_spacing(s, "{")) {
        return 0;
    }

    int cont = 1;
    while (cont) {
        cont = process_declaration(s, prog_out)
            || process_statement(s, prog_out);
    }

    if (!match_string_with_spacing(s, "}")) {
        // Can't unwind processing of statements in compound statement.
        fail_expected(s, "'}'");

        stream_seek(s, pos);
        return 0;
    }

    return 1;
}

/*
    N2176: 6.9.1 function-definition:
        function-definition <- declaration-specifiers declarator declaration-list? compound-statement

    Implemented:
        function_definition <- declaration_specifiers declarator compound_statement

    Examples:
        char dirsep() { abort(); }
        int main() {}
        int main() { putchar('H'); putchar('\n'); }
        int main() { ;;;; }
*/
int match_function_definition(struct stream* s, struct output* prog_out) {
    off_t pos = stream_tell(s);
    if (!match_declaration_specifiers(s)) {
        return 0;
    }

    struct symbol func;
    symbol_init(&func, 0);

    if (!read_declarator(s, &func)) {
        stream_seek(s, pos);
        dump_not_hint(s, __func__);
        return 0;
    }

    if (func.kind != st_function) {
        // Not a function definition. Probably a declaration instead.

        // TODO: Avoid duplicate parsing of declaration_specifiers and
        // declarator shared between the function_definition and declaration
        // rules.
        stream_seek(s, pos);
        return 0;
    }

    assert(func.kind == st_function);

    verify(strcmp(func.name, "main") == 0);

    if (!match_compound_statement(s, prog_out)) {
        stream_seek(s, pos);
        return 0;
    }

    char opcode_halt = 0;
    ssize_t written = write(prog_out->fd, &opcode_halt, 1);
    verify(written == 1);
    return 1;
}

/*
    N2176: 6.9 external-declaration:
        external-declaration <- function-definiton / declaration

    Implemented:
        external_declaration <- function-definition

    Examples:
        char getdirsep() { abort(); }
        int main() {}
        int main() { putchar('H'); putchar('\n'); }
        char lf;
*/
int process_external_declaration(struct stream* s, struct output* prog_out) {
    return match_function_definition(s, prog_out) || process_declaration(s, prog_out);
}

/*
    N2176: 6.9 translation-unit:
        translation-unit <- external-declaration / translation-unit external-declaration

    Implemented:
        translation_unit <- spacing external-declaration*

    Examples:
        int main() {}
        int main() { putchar('H'); } char unused() { abort(); }
        char lf; int main() { ; }
*/
void process_translation_unit(struct stream* s, struct output* prog_out) {
    count_spacing(s);

    while (process_external_declaration(s, prog_out)) {
        // contine
    }
}

int main(int argc, char** argv) {
    verify(argc == 2);

    struct stream s;
    stream_init_openread(&s, argv[1]);

    int outfd = open("out.rw2a", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    verify(outfd != -1);

    struct output prog;
    output_init(&prog, outfd);

    process_translation_unit(&s, &prog);

    int data_start = lseek(prog.fd, 0, SEEK_CUR);
    verify(data_start != -1);

    // Backpatch pointers to data segment, now that we know where the data segment is.
    int i = 0;
    while (i < prog.patches.count) {
        off_t sr = lseek(prog.fd, prog.patches.entries[i].target, SEEK_SET);
        verify(sr != -1);
        int data_offset = prog.patches.entries[i].offset;
        int addr = data_start + data_offset;

        // Write little endian 32 bit pointer.
        int j = 0;
        while (j < 4) {
            char b = addr & 0xFF;
            int wrote = write(prog.fd, &b, 1);
            verify(wrote == 1);
            addr = addr >> 8;
            j = j + 1;
        }

        i = i + 1;
    }

    off_t sr = lseek(prog.fd, data_start, SEEK_SET);
    verify(sr != -1);

    // Write data segment.

    int wrote = write(prog.fd, prog.data.bytes, prog.data.count);
    verify(wrote == prog.data.count);

    int cr = close(outfd);
    verify(cr == 0);

    if (!stream_eof(&s)) {
        write_string(STDOUT_FILENO, "error: unexpected: ");
        stream_dump_tail(&s);
    }
}
