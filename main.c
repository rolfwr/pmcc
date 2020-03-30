/*
    Guide to reading this source code
    =================================

    N2176:
        The latest freely available draft of the C Programming Language standard
        ISO/IEC 9899:2018
        https://web.archive.org/web/20181230041359if_/http://www.open-std.org/jtc1/sc22/wg14/www/abq/c17_updated_proposed_fdis.pdf

    match_...(), count_...(), process_...():
        Recursive decent parsing functions, whose rules are documented using a
        Parsing Expression Grammar (PEG) like syntax.

        https://en.wikipedia.org/wiki/Recursive_descent_parser
        https://en.wikipedia.org/wiki/Parsing_expression_grammar

        Functions return a truth-like value if input stream matched rule.
        When a false-like value is returned, the stream has been rewound back
        to its position before the rule matching started.

        A process_...() function returning a truth-like value will have
        performed actions with site-effects, such as outputting compiled code.
        You should therefore not unwind the stream back past a process_...()
        call that has returned a truth-like value.

        Stream progress made by match_...() and count_...() can safely be
        unwound.
*/

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
    vt_char_constant,
    vt_char_data
};

struct value {
    int type;

    // One of
    char* identifier;
    char char_constant;
    int char_data_offset;
};

void value_init(struct value* val) {
    memset(val, 0, sizeof(struct value));
    val->char_data_offset = -1;
}


struct buffer {
    int count;
    int reserved;
    char* bytes;
};

void buffer_init(struct buffer* buf) {
    buf->count = 0;
    buf->reserved = 16;
    buf->bytes = xmalloc(buf->reserved);
}

int buffer_expand(struct buffer* buf, int count) {
    int index = buf->count;
    buf->count = buf->count + count;
    if (buf->count > buf->reserved) {
        buf->reserved = buf->count * 2;
        buf->bytes = xrealloc(buf->bytes, buf->reserved);
    }
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
    int tempbyteoffsets[16];
    int tempbytecount;
};

void output_init(struct output* o, int fd) {
    o->fd = fd;
    buffer_init(&(o->data));
    constbytetable_init(&(o->constbytes));
    assert(o->constbytes.indexes[42] == -1);
    patchlist_init(&(o->patches));
    symboltable_init(&(o->symbols));

    int i = 0;
    while (i < 16) {
        o->tempbyteoffsets[i] = -1;
        i = i + 1;
    }

    o->tempbytecount = 0;
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

int output_push_tempbyte(struct output* o) {
    verify(o->tempbytecount < 16);
    int offset = o->tempbyteoffsets[o->tempbytecount];
    if (offset == -1) {
        // Allocate a temporary data byte on demand.
        offset = buffer_expand(&(o->data), 1);
        o->tempbyteoffsets[o->tempbytecount] = offset;
    }

    o->tempbytecount = o-> tempbytecount + 1;
    return offset;
}

void output_pop_tempbyte(struct output* o) {
    assert(o->tempbytecount > 0);
    o->tempbytecount = o->tempbytecount - 1;
}

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

    // If we reach this point in the parsing rules, then we expect the not to
    // match any reserved keywords, since they should have been matched by
    // other rules earlier instead.
    assert(strcmp(id, "if") != 0);
    assert(strcmp(id, "while") != 0);

    count_spacing(s);

    return id;
}

/*
    N2176: 6.7.6 direct-declarator:
        direct-declarator <-
            identifier
            / direct-declarator LPAR Declarator RPAR
            / direct-declarator LBRK type-qualifier-list? assignment-expression? RBRK
            / direct-declarator LBRK STATIC type-qualifier-list? assignment-expression RBRK
            / direct-declarator LBRK STATIC type-qualifier-list? STAR RBRK
            / direct-declarator LPAR parameter-type-list RPAR
            / direct-declarator LPAR identifier-list? RPAR

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
    N2176: 6.4.4.1 decimal-constant
        decimal-constant <- nonzero-digit / decimal-constant digit

    Implemented:
        integer_constant <- [0-9]+ spacing

    Examples:
        0
        1
        42
        255
*/
int match_decimal_constant(struct stream* s, struct value* val_out) {
    int count = 0;
    int result = 0;
    while (1) {
        int pos = stream_tell(s);
        int ic = stream_read_char(s);
        char c = ic;
        if (ic == -1 || c < '0' || c > '9') {
            stream_seek(s, pos);
            if (!count) {
                return 0;
            }

            int before = result;
            val_out->type = vt_char_constant;
            val_out->char_constant = result;

            // Catch compile-time overflow
            verify(result >= before);

            count_spacing(s);
            return 1;
        }

        result = result * 10 + (c - '0');
        count = count + 1;
    }
}

/*
    N2176: 6.4.4.1 integer-constant
        integer-constant <-
            decimal-constant integer-suffix?
            / octal-constant integer-suffix?
            / hexidecimal-constant integer-suffix?

    Implemented:
        integer_constant <- decimal_constant

    Examples:
        0
        1
        42
        255
*/
int match_integer_constant(struct stream* s, struct value* val_out) {
    return match_decimal_constant(s, val_out);
}

/*
    N2176: 6.4.4 constant:
        constant <- integer-constant / floating-constant / enumeration-constant / character-constant

    Implemented:
        constant <- interger_constant / character_constant

    Examples:
        'r'
        42
        '"'
        '\n'
*/
int match_constant(struct stream* s, struct value* val_out) {
    assert(val_out->type == vt_none);

    if (match_integer_constant(s, val_out)) {
        return 1;
    }

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
        42
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

off_t output_get_address_here(struct output* out) {
    off_t here = lseek(out->fd, 0, SEEK_CUR);
    verify(here != -1);
    return here;
}

off_t output_emit_pointer_patch_site(struct output* prog_out) {
    off_t patch_site = output_get_address_here(prog_out);

    // write data pointer:
    int i = 0;
    while (i < 4) {
        output_emit_byte(prog_out, 0);
        i = i + 1;
    }

    return patch_site;
}

void output_emit_data_pointer(struct output* prog_out, int data_offset) {
    off_t patch_site = output_emit_pointer_patch_site(prog_out);

    patchlist_push(&prog_out->patches);
    struct patch* addrpatch = patchlist_back(&prog_out->patches);
    addrpatch->offset = data_offset;
    addrpatch->target = patch_site;
}

/*
    Implemented:
        character constants ('c')
        variable identifiers (someVariable)
*/
int output_make_data_byte_offset(struct output* prog_out, struct value* val) {
    if (val->type == vt_char_constant) {
        // character constants ('c')
        return output_get_const_byte_data_offset(prog_out, val->char_constant);
    }

    if (val->type == vt_char_data) {
        assert(val->char_data_offset != -1);
        return val->char_data_offset;
    }

    verify(val->type == vt_identifier);

    // variable identifiers (someVariable)
    struct symbol* sym = symboltable_find(&(prog_out->symbols), val->identifier);
    assert(strcmp(sym->name, val->identifier) == 0);
    verify(sym->kind == st_variable);
    verify(sym->typespec == ts_char);
    verify(sym->dataoffset != -1);
    return sym -> dataoffset;
}

/*
    The RW2a Instruction Set architecture

    https://github.com/rolfwr/rwisa-vm
    http://rolfwr.net/tarpit/
*/
enum {
    opcode_halt,            // 00                 exit(0)
    opcode_output_byte,     // 01 srcptr          putchar(mem[srcptr])
    opcode_branch_if_plus,  // 02 jmpptr srcptr   if (mem[srcptr] < 128) pc = jmpptr
    opcode_subtract,        // 03 dstptr srcptr   mem[dstptr] -= mem[srcptr]
    opcode_input_byte       // 04 dstptr          mem[dstptr] = getchar()
};

void output_emit_subtract(struct output* out, int targetdataoffset, int sourcedataoffset) {
    output_emit_byte(out, opcode_subtract);
    output_emit_data_pointer(out, targetdataoffset);
    output_emit_data_pointer(out, sourcedataoffset);
}

void output_emit_set_zero(struct output* out, int targetdataoffset) {
    output_emit_subtract(out, targetdataoffset, targetdataoffset);
}

void output_emit_negate(struct output* out, int targetdataoffset, int sourcedataoffset) {
    assert(targetdataoffset != sourcedataoffset);
    output_emit_set_zero(out, targetdataoffset);
    output_emit_subtract(out, targetdataoffset, sourcedataoffset);
}

void output_emit_move(struct output* out, int targetdataoffset, int sourcedataoffset) {
    int negtemp = output_push_tempbyte(out);
    output_emit_negate(out, negtemp, sourcedataoffset);
    output_emit_negate(out, targetdataoffset, negtemp);
    output_pop_tempbyte(out);
}

void output_emit_subtract_const(struct output* out, int targetdataoffset, char constval) {
    if (constval == 0) {
        // No need to subtract const zero
        return;
    }

    int constvar = output_get_const_byte_data_offset(out, constval);
    output_emit_subtract(out, targetdataoffset, constvar);
}

void output_emit_add_const(struct output* out, int targeteoffset, char constval) {
    output_emit_subtract_const(out, targeteoffset, (256 - constval) & 255);
}

void output_emit_pointer_value(struct output* out, int pointer_value) {
    int i = 0;
    while (i < 4) {
        output_emit_byte(out, pointer_value & 255);
        pointer_value = pointer_value >> 8;
        i = i + 1;
    }
}

void output_backpatch_address_pointing_here(struct output* out, off_t patchsite) {
    off_t here = output_get_address_here(out);

    off_t seeked = lseek(out->fd, patchsite, SEEK_SET);
    verify(seeked == patchsite);

    output_emit_pointer_value(out, here);

    seeked = lseek(out->fd, here, SEEK_SET);
    verify(seeked == here);
}

 off_t output_emit_jump_with_patch_site(struct output* out) {
         // Jump back to start of loop to recheck conditional expression.1
    int oneconst = output_get_const_byte_data_offset(out, 1);
    output_emit_byte(out, opcode_branch_if_plus);
    off_t patchsite = output_emit_pointer_patch_site(out);
    output_emit_data_pointer(out, oneconst);
    return patchsite;
 }

// Returns jump address patch site or -1 if no patch site was needed because value is always true.
off_t output_emit_jump_if_zero_with_patch_site(struct output* out, struct value* val) {
    off_t onfalsepatchsite = -1;

    if (val->type == vt_char_constant) {

        // Only support constant conditionals right now.
        verify(val->type == vt_char_constant);

        if (val->char_constant == 0) {
            // Need to jump past statement code.
            output_emit_byte(out, opcode_branch_if_plus);
            onfalsepatchsite = output_emit_pointer_patch_site(out);

            int zerooffset = output_get_const_byte_data_offset(out, 0);
            output_emit_data_pointer(out, zerooffset);
        }

    } else {
        int valoffset = output_make_data_byte_offset(out, val);

        int testrange = output_push_tempbyte(out);
        output_emit_move(out, testrange, valoffset);

        // Handle range 1 -- 128 indicating true:
        // 255 --> 254   Fall through
        //   0 --> 255   Fall through
        //   1 -->   0   Jump to if-body (true)
        output_emit_subtract_const(out, testrange, 1);
        output_emit_byte(out, opcode_branch_if_plus);
        int ontruepatchsite = output_emit_pointer_patch_site(out);
        output_emit_data_pointer(out, testrange);

        // Handle range 129 -- 255 indicating true:
        // 255 --> 254 --> 255   Fall through to if-body (true)
        //   0 --> 255 -->   0   Jump past if-body (false)
        //   1 -->   0 -->   1   N/A, already jumped to if-body above (true)
        output_emit_add_const(out, testrange, 1);
        output_emit_byte(out, opcode_branch_if_plus);
        onfalsepatchsite = output_emit_pointer_patch_site(out);
        output_emit_data_pointer(out, testrange);
        output_pop_tempbyte(out);

        output_backpatch_address_pointing_here(out, ontruepatchsite);
    }

    return onfalsepatchsite;
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
        42
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
    struct value* arg0 = list_back(&args);
    int data_offset = output_make_data_byte_offset(prog_out, arg0);

    output_emit_byte(prog_out, opcode_output_byte);
    output_emit_data_pointer(prog_out, data_offset);

    // putchar() returns the given argument unless error occurs.
    memcpy(val_out, arg0, sizeof(struct value));
    return 1;
}
/*
    N2176: 6.5.3 unary-operator:
        AND / STAR / PLUS / MINUS / TILDE / BANG

    Implemented:
        BANG spacing

    Examples:
        !
*/
char match_unary_operator(struct stream* s) {
    off_t pos = stream_tell(s);
    int ic = stream_read_char(s);
    if (ic == -1) {
        return 0;
    }
    char c = ic;

    if (c == '!') {
        return c;
    }

    stream_seek(s, pos);
    return 0;
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
        unary_expression <-
            postfix_expression
            / unary_operator (unary_expression / fail)

    Examples:
        !error_code
        'H'
        42
        putchar('H')
        abort()
*/
int process_unary_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    if (process_postfix_expression(s, val_out, prog_out)) {
        return 1;
    }

    char op = match_unary_operator(s);
    if (!op) {
        return 0;
    }

    verify(op == '!');

    if (!process_unary_expression(s, val_out, prog_out)) {
        fail_expected(s, "unary expression after '!'");
        return 0;
    }

    int notdata = buffer_expand(&(prog_out->data), 1);
    output_emit_set_zero(prog_out, notdata);


    off_t onfalse_output1 = output_emit_jump_if_zero_with_patch_site(prog_out, val_out);
    off_t ontrue_output0 = output_emit_jump_with_patch_site(prog_out);

    output_backpatch_address_pointing_here(prog_out, onfalse_output1);
    output_emit_add_const(prog_out, notdata, 1);

    output_backpatch_address_pointing_here(prog_out, ontrue_output0);

    value_init(val_out);
    val_out->type = vt_char_data;
    val_out->char_data_offset = notdata;
    return 1;
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

int match_minus(struct stream* s) {
    off_t pos = stream_tell(s);
    if (!match_string(s, "-")) {
        return 0;
    }

    off_t after = stream_tell(s);
    int ic = stream_read_char(s);
    if (ic == '-' || ic == '=' || ic == '>') {
        note_processed_as(s, pos, "not minus binary");
        // Not a minus
        stream_seek(s, pos);
        return 0;
    }

    stream_seek(s, after);
    count_spacing(s);
    return 1;
}

/*
    N2176: additive-expression:
        additive-expression <-
            multiplicative-expression
            / addative-expression + multiplicative-expression
            / addative-expression - multiplicative-expression

    Implemented:
        unary_expression (MINUS unary_expression)
        MINUS <-  '-' ![\-=>] spacing

    Examples:
        count - 1
        digit - '0'
        putchar('H')
        abort()
*/
int process_additive_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    if (!process_unary_expression(s, val_out, prog_out)) {
        return 0;
    }

    if (!match_minus(s)) {
        return 1;
    }

    struct value rhs;
    value_init(&rhs);

    if (!process_unary_expression(s, &rhs, prog_out)) {
        fail_expected(s, "unary expression after binary '-' operator");
        return 0;
    }

    // TODO: Avoid needless use of data area.

    int resultdata = buffer_expand(&(prog_out->data), 1);
    int lhsdata = output_make_data_byte_offset(prog_out, val_out);
    int rhsdata = output_make_data_byte_offset(prog_out, &rhs);

    output_emit_move(prog_out, resultdata, lhsdata);
    output_emit_subtract(prog_out, resultdata, rhsdata);

    value_init(val_out);
    val_out->type = vt_char_data;
    val_out->char_data_offset = resultdata;

    return 1;
}

/*
    N2176: 6.5.15 conditional-expression:
        conditional-expression <-
            logical-OR-expression
            / logical-OR-expression QUERY expression COLON conditional-expression

    Implemented:
        conditional_expression <- additive_expression

    Examples:
        count - 1
        digit - '0'
        putchar('H')
        abort()
*/
int process_conditional_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    return process_additive_expression(s, val_out, prog_out);
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

/*
    N2176: 6.5.16: assignment-expression:
        assignment-expression <- conditional-expression / unary-expression assignment-operator assignment-expression

    Implemented:
        assignment_expression <- conditional-expression (assignment_operator (assignment_expression / fail))?

    Examples:
        count = count - 1
        val = digit - '0'
        42
        !error_code
        putchar('H')
        abort()

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
        int vardataoffset = variable->dataoffset;

        if (aexpr.type == vt_char_constant) {
            int negconstoffset = output_get_const_byte_data_offset(prog_out, (256 - aexpr.char_constant) & 255);
            output_emit_negate(prog_out, vardataoffset, negconstoffset);
        } else {
            int sourceoffset = output_make_data_byte_offset(prog_out, &aexpr);
            output_emit_move(prog_out, vardataoffset, sourceoffset);
        }

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
        'a', 42, '\n'
        foo = 'A', bar = 'B'
        count = count - 1, val = digit - '0', 42, !error_code
        'C', main, bar = 'D', baz, 42
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
        count = count - 1
        val = digit - '0'
        42
        error_code
        putchar('H')
        abort()
*/
int process_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    return process_assignment_expression(s, val_out, prog_out);
}

/*
    N2176: 6.8.3 expression-statement:
        expression-statement <- expression? SEMI

    Implemented:
        expression (SEMI / fail) / SEMI
        SEMI <- ';' spacing

    Examples:
        count = count - 1;
        putchar('H');
        error_code;
        42;
        ;
*/
int process_expression_statement(struct stream* s, struct output* prog_out) {
    off_t pos = stream_tell(s);
    struct value val;
    value_init(&val);

    int saw_expression = process_expression(s, &val, prog_out);
    int saw_semi = match_string_with_spacing(s, ";");
    if (saw_expression && !saw_semi) {
        // Can't unwind processing of expression
        fail_expected(s, "';' after expression");
        stream_seek(s, pos);
        return 0;
    }

    return saw_semi;
}

int process_statement(struct stream* s, struct output* prog_out);

/*
    N2176: 6.8.4 selection-statement:
        selection-statement <-
            IF LPAR expression RPAR statement
            / IF LPAR expression RPAR statement ELSE statement
            / SWITCH LPAR expression RPAR statement

    Implemented:
        selection_statement <- IF (LPAR expression RPAR statement / fail)
        LPAR <-  '(' spacing
        RPAR <-  ')' spacing

    Examples:
        if (1) putchar('H');
        if (!ok) retries = retries - 1;
        if (ec = get_error()) ;
        if ('H') 'i';
*/
int process_selection_statement(struct stream* s, struct output* prog_out) {
    if (!match_word(s, "if")) {
        return 0;
    }

    if (!match_string_with_spacing(s, "(")) {
        fail_expected(s, "'(' after 'if'");
        return 0;
    }

    struct value val;
    value_init(&val);
    if (!process_expression(s, &val, prog_out)) {
        fail_expected(s, "condition expression after 'if ('");
        return 0;
    }

    if (!match_string_with_spacing(s, ")")) {
        fail_expected(s, "')' closing if condition expression");
        return 0;
    }

    off_t onfalsepatchsite = output_emit_jump_if_zero_with_patch_site(prog_out, &val);

    if (!process_statement(s, prog_out)) {
        fail_expected(s, "if body statement");
        return 0;
    }

    if (onfalsepatchsite != -1) {
        output_backpatch_address_pointing_here(prog_out, onfalsepatchsite);
    }

    return 1;
}

/*
    N2176: 6.8.5 iteration-statement:
        iteration-statement <-
            WHILE LPAR expression RPAR statement
            / DO statement WHILE LPAR expression RPAR SEMI
            / FOR LPAR expression? SEMI expression? SEMI expersion? RPAR statement
            / FOR LPAR declaration expression? SEMI expression? SEMI expersion? RPAR statement

    Implemented:
        iteration_statement <- WHILE (LPAR expression RPAR statement / fail)
        LPAR <-  '(' spacing
        RPAR <-  ')' spacing

    Examples:
        while (count) { count = count - 1; putchar('*'); }
        while (process()) ;
        while (0) 'x';
*/
int process_iteration_statement(struct stream* s, struct output* prog_out) {
    if (!match_word(s, "while")) {
        return 0;
    }

    if (!match_string_with_spacing(s, "(")) {
        fail_expected(s, "'(' after 'while'");
        return 0;
    }

    off_t loop_start = output_get_address_here(prog_out);

    struct value val;
    value_init(&val);
    if (!process_expression(s, &val, prog_out)) {
        fail_expected(s, "condition expression after 'while ('");
        return 0;
    }

    if (!match_string_with_spacing(s, ")")) {
        fail_expected(s, "')' closing while condition expression");
        return 0;
    }

    off_t onfalsepatchsite = output_emit_jump_if_zero_with_patch_site(prog_out, &val);

    if (!process_statement(s, prog_out)) {
        fail_expected(s, "while body statement");
        return 0;
    }

    // Jump back to start of loop to recheck conditional expression.1
    int oneconst = output_get_const_byte_data_offset(prog_out, 1);
    output_emit_byte(prog_out, opcode_branch_if_plus);
    output_emit_pointer_value(prog_out, loop_start);
    output_emit_data_pointer(prog_out, oneconst);

    if (onfalsepatchsite != -1) {
        output_backpatch_address_pointing_here(prog_out, onfalsepatchsite);
    }

    return 1;
}

int process_compound_statement(struct stream* s, struct output* prog_out);

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
        statement <- compound_statement / selection_statement / iteration_statement / expression_statement

    Examples:
        {}
        { putchar('H'); putchar('i'); }
        if (1) putchar('H');
        while (count) { count = count - 1; putchar('*'); }
        'H';
        42;
        error_code = 4;
        putchar('H');
        ;
*/
int process_statement(struct stream* s, struct output* prog_out) {
    // We decend into selection_statement before expression_statement to avoid
    // needlessly trying to parse keywords such as "if" as identifiers.
    return process_compound_statement(s, prog_out)
        || process_selection_statement(s, prog_out)
        || process_iteration_statement(s, prog_out)
        || process_expression_statement(s, prog_out);
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
        { 'H'; error_code = 4; putchar('H'); ; 42 - 3; !ok; }
        { if (1) { }; while (0) ; }
        { { } }
*/
int process_compound_statement(struct stream* s, struct output* prog_out) {
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
int process_function_definition(struct stream* s, struct output* prog_out) {
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

    if (!process_compound_statement(s, prog_out)) {
        stream_seek(s, pos);
        return 0;
    }

    output_emit_byte(prog_out, opcode_halt);
    return 1;
}

/*
    N2176: 6.9 external-declaration:
        external-declaration <- function-definiton / declaration

    Implemented:
        external_declaration <- function-definition / declaration

    Examples:
        char getdirsep() { abort(); }
        int main() {}
        int main() { putchar('H'); putchar('\n'); }
        char lf;
*/
int process_external_declaration(struct stream* s, struct output* prog_out) {
    return process_function_definition(s, prog_out) || process_declaration(s, prog_out);
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
        char c;int main(){c=10;while(c){putchar('*');c=c-1;}}
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

    int data_start = output_get_address_here(&prog);

    // Backpatch pointers to data segment, now that we know where the data segment is.
    int i = 0;
    while (i < prog.patches.count) {
        off_t sr = lseek(prog.fd, prog.patches.entries[i].target, SEEK_SET);
        verify(sr != -1);
        int data_offset = prog.patches.entries[i].offset;
        int addr = data_start + data_offset;

        // Write little endian 32 bit pointer.
        output_emit_pointer_value(&prog, addr);
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
