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

// value storage
enum {
    vs_none,
    vs_unresolved_identifier,
    vs_constant,
    vs_data_offset,
    vs_pc_offset
};


// type specifiers
enum {
    ts_none,
    ts_unresolved,
    ts_void,
    ts_char,
    ts_int,
    ts_function
};

struct value {
    int storage;
    int typespecifier;

    char* identifier;
    char char_constant;
    int data_offset;

    int ispointer;

    // compilation specific
    int funcaddr;
    int returnpatchsite;
};

void value_init(struct value* val) {
    memset(val, 0, sizeof(struct value));
    val->data_offset = -1;
    val->funcaddr = -1;
    val->returnpatchsite = -1;
}

// Generic and dynamically sized array.
// Type specific dynamic arrays such as struct buffer and struct patchlist use
// struct vector for low-level memory management.

struct vector {
    int element_size;
    int count;
    int reserved_count;
    void* allocation;
};

void vector_init(struct vector* vec, int element_size, int reserve_count) {
    vec->element_size = element_size;
    vec->count = 0;
    vec->reserved_count = reserve_count;
    vec->allocation = xmalloc(vec->reserved_count * vec->element_size);
}

int vector_expand(struct vector* vec, int count) {
    int index = vec->count;
    vec->count = vec->count + count;
    if (vec->count > vec->reserved_count) {
        vec->reserved_count = vec->count * 2;
        vec->allocation = xrealloc(vec->allocation, vec->reserved_count * vec->element_size);
    }
    return index;
}

struct buffer {
    struct vector bytes;
};

void buffer_init(struct buffer* buf) {
    vector_init(&(buf->bytes), 1, 16);
}

int buffer_expand(struct buffer* buf, int count) {
    return vector_expand(&(buf->bytes), count);
}

char* buffer_at(struct buffer* buf, int index) {
    char* bytes = (char*)(buf->bytes.allocation);
    return &(bytes[index]);
}

int buffer_size(struct buffer* buf) {
    return buf->bytes.count;
}

void* buffer_data(struct buffer* buf) {
    return buf->bytes.allocation;
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
    struct vector patches;
};

void patchlist_init(struct patchlist* pl) {
    vector_init(&(pl->patches), sizeof(struct patch), 16);
}

void patchlist_push(struct patchlist* pl) {
    vector_expand(&(pl->patches), 1);
}

struct patch* patchlist_at(struct patchlist* pl, int index) {
    struct patch* elements = (struct patch*)(pl->patches.allocation);
    return &(elements[index]);
}

int patchlist_count(struct patchlist* pl) {
    return pl->patches.count;
}

struct patch* patchlist_back(struct patchlist* pl) {
    return patchlist_at(pl, patchlist_count(pl) - 1);
}

struct symbol {
    struct value val;
};

void symbol_init(struct symbol* sym, char* name) {
    value_init(&(sym->val));
    sym->val.identifier = name;
}

int value_sizeof(struct value* val) {
    if (val->ispointer) {
        return 4;
    }

    verify(val->typespecifier == ts_char);
    return 1;
}

struct symboltable {
    struct vector symbols;
};

void symboltable_init(struct symboltable* symtab) {
    vector_init(&(symtab->symbols), sizeof(struct symbol), 16);
}

struct symbol* symboltable_find(struct symboltable* symtab, char* name) {
    int i = 0;
    struct symbol* elements = (struct symbol*)(symtab->symbols.allocation);
    while (i < symtab->symbols.count) {
        struct symbol* entry = &(elements[i]);
        if (strcmp(name, entry->val.identifier) == 0) {
            return entry;
        }

        i = i + 1;
    }
    return 0;
}

struct symbol* symboltable_add(struct symboltable* symtab, char* name) {
    assert(symboltable_find(symtab, name) == 0);
    int index = vector_expand(&(symtab->symbols), 1);
    struct symbol* elements = (struct symbol*)(symtab->symbols.allocation);
    struct symbol* new_entry = &(elements[index]);
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
    int mainjumppatchsite;
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
    o->mainjumppatchsite = -1;
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
        VOID <- 'void' !id_char spacing
        CHAR <- 'char' !id_char spacing
        INT <- 'char' !id_char spacing

    Examples (C-like syntax):
        "char "
        "int\r\n"
*/
int match_type_specifier(struct stream* s) {
    if (match_word(s, "void")) {
        return ts_void;
    }

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
        "void "
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

    decl_out->val.identifier = name;

    off_t pos = stream_tell(s);

    if (!match_string_with_spacing(s, "(")) {
        stream_seek(s, pos);
        decl_out->val.typespecifier = ts_unresolved;
        return 1;
    }

    if (!match_string_with_spacing(s, ")")) {
        fail_expected(s, "')'");
        return 0;
    }

    decl_out->val.typespecifier = ts_function;
    return 1;
}

int match_string_not_followed_by_char_but_with_spaces(struct stream* s, const char* str, const char* disallowed_chars) {
    off_t pos = stream_tell(s);
    if (!match_string(s, str)) {
        return 0;
    }

    off_t after = stream_tell(s);
    int ic = stream_read_char(s);
    while (*disallowed_chars) {
        if (ic == *disallowed_chars) {
            stream_seek(s, pos);
            return 0;
        }

        disallowed_chars = disallowed_chars + 1;
    }

    stream_seek(s, after);
    count_spacing(s);
    return 1;
}

/*
    N2176 6.7.7 pointer:
        pointer <- STAR type_qualifier_list? / STAR  type_qualifier_list? pointer

    Implemented:
        pointer <- STAR
        STAR <-  '*' ![=] spacing
*/
int match_pointer(struct stream* s) {
    return match_string_not_followed_by_char_but_with_spaces(s, "*", "=");
}

/*
    N2176: 6.7.6 declarator:
        delarator <- pointer? direct-declarator

    Implemented:
        declarator <- pointer? direct_declarator

    Examples:
        main()
        main ( )
        byte_count
        * str
*/
int read_declarator(struct stream* s, struct symbol* decl_out) {
    off_t pos = stream_tell(s);

    int ispointer = match_pointer(s);

    if (!read_direct_declarator(s, decl_out)) {
        stream_seek(s, pos);
        return 0;
    }

    decl_out->val.ispointer = ispointer;

    return 1;
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
            val_out->storage = vs_constant;
            val_out->typespecifier = ts_char;
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
    assert(val_out->storage == vs_none);

    if (match_integer_constant(s, val_out)) {
        return 1;
    }

    int charconst = read_character_constant(s);

    if (charconst == -1) {
        return 0;
    }

    val_out->storage = vs_constant;
    val_out->typespecifier = ts_char;
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

int process_expression(struct stream* s, struct value* val_out, struct output* prog_out);

/*
    N2176: 6.5.1 1 primary-expression:
        primary-expression <- identifier / constant / string-literal / LPAR expression RPAR / generic-selection

    Implemented:
        primary_expression <- identifier / constant / LPAR (expression RPAR / fail)
        LPAR <-  '(' spacing
        RPAR <-  ')' spacing
    Examples:
        main
        error_code
        42
        '\n'
        (digit - '0')
*/
int process_primary_expression(struct stream* s, struct value* out_val, struct output* prog_out) {
    char* id = read_identifier(s);
    if (id) {
        out_val->storage = vs_unresolved_identifier;
        out_val->typespecifier = ts_unresolved;
        out_val->identifier = id;
        return 1;
    }

    if (match_constant(s, out_val)) {
        return 1;
    }

    if (!match_string_with_spacing(s, "(")) {
        return 0;
    }

    if (!process_expression(s, out_val, prog_out)) {
        fail_expected(s, "expression after '('");
        return 0;
    }

    if (!match_string_with_spacing(s, ")")) {
        fail_expected(s, "')' closing nested expression");
        return 0;
    }

    return 1;
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

int value_is_of_basic_type(struct value* val, int basictypespec) {
    if (val->ispointer) {
        return 0;
    }

    return val->typespecifier == basictypespec;
}

/*
    Implemented:
        character constants ('c')
        variable identifiers (someVariable)
*/
int output_make_data_byte_offset(struct output* prog_out, struct value* val) {
    if (val->storage == vs_constant && val->typespecifier == ts_char) {
        // character constants ('c')
        return output_get_const_byte_data_offset(prog_out, val->char_constant);
    }

    if (val->storage == vs_data_offset && val->typespecifier == ts_char) {
        assert(val->data_offset != -1);
        return val->data_offset;
    }

    verify(val->storage == vs_unresolved_identifier);

    // variable identifiers (someVariable)
    struct symbol* sym = symboltable_find(&(prog_out->symbols), val->identifier);
    assert(strcmp(sym->val.identifier, val->identifier) == 0);
    verify(sym->val.storage == vs_data_offset);
    verify(value_is_of_basic_type(&(sym->val), ts_char));
    verify(sym->val.data_offset != -1);
    return sym->val.data_offset;
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

void output_emit_add(struct output* out, int targetdataoffset, int sourcedataoffset) {
    int negdata = output_push_tempbyte(out);
    output_emit_negate(out, negdata, sourcedataoffset);
    output_emit_subtract(out, targetdataoffset, negdata);
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

void output_emit_runtime_patch_move(struct output* out, int targetpc, int sourcedataoffset) {
    int negtemp = output_push_tempbyte(out);
    output_emit_negate(out, negtemp, sourcedataoffset);

    // patching set zero
    output_emit_byte(out, opcode_subtract);
    output_emit_pointer_value(out, targetpc);
    output_emit_pointer_value(out, targetpc);

    // patching add (subtract negative)
    output_emit_byte(out, opcode_subtract);
    output_emit_pointer_value(out, targetpc);
    output_emit_data_pointer(out, negtemp);

    output_pop_tempbyte(out);
}

void output_backpatch_address_pointing_here(struct output* out, off_t patchsite) {
    off_t here = output_get_address_here(out);

    off_t seeked = lseek(out->fd, patchsite, SEEK_SET);
    verify(seeked == patchsite);

    output_emit_pointer_value(out, here);

    seeked = lseek(out->fd, here, SEEK_SET);
    verify(seeked == here);
}

off_t output_emit_jump_if_plus_with_patch_site(struct output* out, int datacharoffset) {
    output_emit_byte(out, opcode_branch_if_plus);
    off_t patchsite = output_emit_pointer_patch_site(out);
    output_emit_data_pointer(out, datacharoffset);
    return patchsite;
}

void output_emit_jump_back_to_if_plus(struct output* out, off_t target_address, int datacharoffset) {
    output_emit_byte(out, opcode_branch_if_plus);
    output_emit_pointer_value(out, target_address);
    output_emit_data_pointer(out, datacharoffset);
}

off_t output_emit_jump_with_patch_site(struct output* out) {
    int zeroconst = output_get_const_byte_data_offset(out, 0);
    return output_emit_jump_if_plus_with_patch_site(out, zeroconst);
}

void output_emit_jump_back_to(struct output* out, off_t target_address) {
    int zeroconst = output_get_const_byte_data_offset(out, 0);
    output_emit_jump_back_to_if_plus(out, target_address, zeroconst);
}

// Returns jump address patch site or -1 if no patch site was needed because value is always true.
off_t output_emit_jump_if_zero_with_patch_site(struct output* out, struct value* val) {
    off_t onfalsepatchsite = -1;

    if (val->storage == vs_constant && val->typespecifier == ts_char) {
        if (val->char_constant == 0) {
            // Need to jump past statement code.
            onfalsepatchsite = output_emit_jump_with_patch_site(out);
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
        int ontruepatchsite = output_emit_jump_if_plus_with_patch_site(out, testrange);

        // Handle range 129 -- 255 indicating true:
        // 255 --> 254 --> 255   Fall through to if-body (true)
        //   0 --> 255 -->   0   Jump past if-body (false)
        //   1 -->   0 -->   1   N/A, already jumped to if-body above (true)
        output_emit_add_const(out, testrange, 1);
        onfalsepatchsite = output_emit_jump_if_plus_with_patch_site(out, testrange);

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
    assert(val_out->storage == vs_none);

    if (!process_primary_expression(s, val_out, prog_out)) {
        return 0;
    }

    assert(val_out->storage != vs_none);
    assert(val_out->typespecifier != ts_none);

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

    verify(val_out->storage == vs_unresolved_identifier);

    struct symbol* func = symboltable_find(&(prog_out->symbols), val_out->identifier);
    if (func != 0) {
        verify(func->val.typespecifier == ts_function);
        verify(func->val.storage = vs_pc_offset);

        // For now, only support stackless, non-recursive functions.
        verify(args.count == 0);

        // Emit code to patch instruction to jump back after function call.
        // The address to jump back to will be stored in the data segment, and
        // will be compied to the patch site right before jumping to the
        // function.

        // We'll fill in the return address value later. For now, just reserve
        // the space.
        int returnaddrdata = buffer_expand(&(prog_out->data), 4);
        assert(func->val.returnpatchsite != -1);

        for (int i = 0; i < 4; ++i) {
            off_t pctarget = func->val.returnpatchsite + i;
            output_emit_runtime_patch_move(prog_out, pctarget, returnaddrdata + i);
        }

        assert(func->val.funcaddr != -1);
        output_emit_jump_back_to(prog_out, func->val.funcaddr);

        int returnaddrvalue = output_get_address_here(prog_out);

        // Now that we know the exact address to return to, store that in
        // the data segement where we will copy the value from at runtime.
        for (int i = 0; i < 4; ++i) {
            *buffer_at(&(prog_out->data), returnaddrdata + i) = returnaddrvalue & 255;
            returnaddrvalue = returnaddrvalue >> 8;
        }

        return 1;
    }

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
        unary-operator <- AND / STAR / PLUS / MINUS / TILDE / BANG

    Implemented:
        unary_operator <- ( AND / BANG ) spacing
        AND <- '&' ![&]
        BANG <- '!' ![=]

    Examples:
        !
        &
*/
char match_unary_operator(struct stream* s) {
    char c = 0;
    if (match_string_not_followed_by_char_but_with_spaces(s, "&", "&")) {
        c = '&';
    } else if (match_string_not_followed_by_char_but_with_spaces(s, "!", "=")) {
        c = '!';
    }

    if (!c) {
        return 0;
    }

    count_spacing(s);
    return c;
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

    if (op == '&') {
        if (!process_unary_expression(s, val_out, prog_out)) {
            fail_expected(s, "unary expression after '!'");
            return 0;
        }

        // Only one level of pointers right now.
        verify(!val_out->ispointer);

        // Implement getting address
        //int data_index = output_make_data_byte_offset(prog_out, val_out);

        val_out->ispointer = 1;
        int addressdata = buffer_expand(&(prog_out->data), value_sizeof(val_out));

        // TODO: emit code to initialize addressdata, which will be backpatched
        // with actual address values once we can calculate it from the start
        // of the data segment and data_index.

        val_out->storage = vs_data_offset;
        val_out->data_offset = addressdata;
        // The typespecifier is retained.

        return 1;
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
    val_out->storage = vs_data_offset;

    // Deviation from standard C. We're using char rather than int to store
    // bools to better support 8-bit targets.
    val_out->typespecifier = ts_char;
    val_out->data_offset = notdata;
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

// PLUS <- '-' ![\-+=] spacing
// PLUS <- '+' ![+=] spacing
char match_plus_or_minus(struct stream* s) {
    if (match_string_not_followed_by_char_but_with_spaces(s, "+", "+=")) {
        return '+';
    } else if (match_string_not_followed_by_char_but_with_spaces(s, "-", "-=>")) {
        return '-';
    }

    return 0;
}

/*
    N2176: additive-expression:
        additive-expression <-
            multiplicative-expression
            / addative-expression + multiplicative-expression
            / addative-expression - multiplicative-expression

    Implemented:
        unary_expression (plus_or_minus unary_expression / fail)*

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

    int resultdata = -1;
    char op = match_plus_or_minus(s);
    while (op) {
        struct value rhs;
        value_init(&rhs);

        if (!process_unary_expression(s, &rhs, prog_out)) {
            fail_expected(s, "unary expression after binary '-' operator");
            return 0;
        }

        // Do subtract or add

        if (resultdata == -1) {
            resultdata = buffer_expand(&(prog_out->data), 1);
        }

        int lhsdata = output_make_data_byte_offset(prog_out, val_out);
        int rhsdata = output_make_data_byte_offset(prog_out, &rhs);

        output_emit_move(prog_out, resultdata, lhsdata);
        if (op == '-') {
            output_emit_subtract(prog_out, resultdata, rhsdata);
        } else {
            assert(op == '+');
            output_emit_add(prog_out, resultdata, rhsdata);
        }

        value_init(val_out);
        val_out->storage = vs_data_offset;
        val_out->typespecifier = ts_char;
        val_out->data_offset = resultdata;

        op = match_plus_or_minus(s);
    }

    return 1;
}

/*
    N2176: 6.5.8: relational-expression
        relational-expression <-
            shift-expression
            / relational-expression LT shift-expression
            / relational-expression GT shift-expression
            / relational-expression LE shift-expression
            / relational-expression GE shift-expression

    Implemented:
        relational_expression <-
            additive_expression (LT (additive_expression / fail))?
            LT <- '<' ![=] spacing

    Example:
        count - 1 < reserved
        digit < '0'
        putchar('H')
        abort()
*/
int process_relational_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    if (!process_additive_expression(s, val_out, prog_out)) {
        return 0;
    }

    int resultdata = -1;
    while (match_string_not_followed_by_char_but_with_spaces(s, "<", "=")) {
        struct value rhs;
        value_init(&rhs);

        if (!process_additive_expression(s, &rhs, prog_out)) {
            fail_expected(s, "additive expression after relational operator");
            return 0;
        }

        // Compare
        if (resultdata == -1) {
            resultdata = buffer_expand(&(prog_out->data), 1);
        }

        int lhsdata = output_make_data_byte_offset(prog_out, val_out);
        int rhsdata = output_make_data_byte_offset(prog_out, &rhs);

        int on_lhspos = output_emit_jump_if_plus_with_patch_site(prog_out, lhsdata);

        // lhsdata < 0

        int on_true = output_emit_jump_if_plus_with_patch_site(prog_out, rhsdata);


        off_t samesign_label = output_get_address_here(prog_out);
        // (lhsdata < 0 && rhsdata < 0) || (lhsdata >= 0 && rhsdata >= 0)

        // 2 - 1  -->   1  -->  false  -->  0
        // 2 - 2  -->   0  -->  false  -->  0
        // 1 - 2  -->  -2  -->  true   -->  1
        output_emit_move(prog_out, resultdata, lhsdata);
        output_emit_subtract(prog_out, resultdata, rhsdata);

        int on_false = output_emit_jump_if_plus_with_patch_site(prog_out, resultdata);
        // (lhsdata < 0 && rhsdata >= 0)

        // True
        output_backpatch_address_pointing_here(prog_out, on_true);

        // (((lhsdata < 0 && rhsdata < 0) || (lhsdata >= 0 && rhsdata >= 0)) && (lhs - rhs) <= 0) || (lhsdata < 0 && rhsdata >= 0)
        output_emit_set_zero(prog_out, resultdata);
        output_emit_add_const(prog_out, resultdata, 1);

        int on_end = output_emit_jump_with_patch_site(prog_out);

        output_backpatch_address_pointing_here(prog_out, on_lhspos);
        // lhsdata >= 0

        output_emit_jump_back_to_if_plus(prog_out, samesign_label, rhsdata);
        // lhsdata >= 0 && rhs < 0 --> false

        // False
        output_backpatch_address_pointing_here(prog_out, on_false);
        output_emit_set_zero(prog_out, resultdata);

        output_backpatch_address_pointing_here(prog_out, on_end);
        value_init(val_out);
        val_out->storage = vs_data_offset;
        val_out->typespecifier = ts_char;
        val_out->data_offset = resultdata;
    }

    return 1;
}

/*
    N2176: 6.5.15 conditional-expression:
        conditional-expression <-
            logical-OR-expression
            / logical-OR-expression QUERY expression COLON conditional-expression

    Implemented:
        conditional_expression <- relational_expression

    Examples:
        count - 1
        digit - '0'
        putchar('H')
        abort()
*/
int process_conditional_expression(struct stream* s, struct value* val_out, struct output* prog_out) {
    return process_relational_expression(s, val_out, prog_out);
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
            fail_expected(s, "assignment expression after assignment operator");
            stream_seek(s, pos);
        }

        // Handle specifically:
        //     someVariableName = '?'

        verify(val_out->storage == vs_unresolved_identifier);

        struct symbol* variable = symboltable_find(&(prog_out->symbols), val_out->identifier);
        verify(variable != 0);
        assert(strcmp(variable->val.identifier, val_out->identifier) == 0);

        verify(variable->val.storage == vs_data_offset);

        verify(value_is_of_basic_type(&(variable->val), ts_char));
        int vardataoffset = variable->val.data_offset;

        if (aexpr.storage == vs_constant) {
            verify(aexpr.typespecifier == ts_char);
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

    verify(symboltable_find(&(prog_out->symbols), decllist.val.identifier) == 0);

    struct symbol* newvar = symboltable_add(&(prog_out->symbols), decllist.val.identifier);

    assert(newvar != 0);
    assert(strcmp(newvar->val.identifier, decllist.val.identifier) == 0);
    memcpy(newvar, &decllist, sizeof(struct symbol));

    newvar->val.typespecifier = typespec;
    newvar->val.storage = vs_data_offset;

    // Make appropriate amount of room for the new variable, and remember where
    // we put it.
    newvar->val.data_offset = buffer_expand(&(prog_out->data), value_sizeof(&(newvar->val)));

    assert(symboltable_find(&(prog_out->symbols), decllist.val.identifier) == newvar);

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

    if (func.val.typespecifier != ts_function) {
        // Not a function definition. Probably a declaration instead.

        // TODO: Avoid duplicate parsing of declaration_specifiers and
        // declarator shared between the function_definition and declaration
        // rules.
        stream_seek(s, pos);
        return 0;
    }

    assert(func.val.typespecifier == ts_function);

    verify(symboltable_find(&(prog_out->symbols), func.val.identifier) == 0);
    struct symbol* newfunc = symboltable_add(&(prog_out->symbols), func.val.identifier);
    memcpy(newfunc, &func, sizeof(struct symbol));
    assert(strcmp(newfunc->val.identifier, func.val.identifier) == 0);

    char ismain = strcmp(func.val.identifier, "main") == 0;
    if (ismain) {
        int patchsite = prog_out->mainjumppatchsite;
        prog_out->mainjumppatchsite = 0;
        if (patchsite > 0) {
            output_backpatch_address_pointing_here(prog_out, patchsite);
        }
    } else {
        if (prog_out->mainjumppatchsite == -1) {
            prog_out->mainjumppatchsite = output_emit_jump_with_patch_site(prog_out);
        }
    }

    newfunc->val.funcaddr = output_get_address_here(prog_out);

    if (!process_compound_statement(s, prog_out)) {
        stream_seek(s, pos);
        return 0;
    }

    if (ismain) {
        output_emit_byte(prog_out, opcode_halt);
    } else {
        newfunc->val.returnpatchsite = output_emit_jump_with_patch_site(prog_out);
    }
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
    while (i < patchlist_count(&(prog.patches))) {
        struct patch* entry = patchlist_at(&(prog.patches), i);
        off_t sr = lseek(prog.fd, entry->target, SEEK_SET);
        verify(sr != -1);
        int data_offset = entry->offset;
        int addr = data_start + data_offset;

        // Write little endian 32 bit pointer.
        output_emit_pointer_value(&prog, addr);
        i = i + 1;
    }

    off_t sr = lseek(prog.fd, data_start, SEEK_SET);
    verify(sr != -1);

    // Write data segment.

    int wrote = write(prog.fd, buffer_data(&(prog.data)), buffer_size(&(prog.data)));
    verify(wrote == buffer_size(&(prog.data)));

    int cr = close(outfd);
    verify(cr == 0);

    if (!stream_eof(&s)) {
        write_string(STDOUT_FILENO, "error: unexpected: ");
        stream_dump_tail(&s);
    }
}
