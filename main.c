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
    int len = strlen(str);
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

    char c = '0' + value;
    write(fd, &c, 1);
}

void verify_fail(const char* expr, const char* file, int line, const char* function) {
    int err = STDERR_FILENO;
    write_string(err, "verify: ");
    write_string(err, file);
    write_string(err, ":");
    write_int(err, line);
    write_string(err, ": ");
    write_string(err, function);
    write_string(err, ": Expectation '");
    write_string(err, expr);
    write_string(err, "' failed.\n");
    abort();
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

void stream_read(struct stream* s, void* buf, size_t nbytes) {
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

void fail_expected(struct stream* s, char* expected) {
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
    struct patch entries[16];
    int count;
};

void patchlist_init(struct patchlist* pl) {
    memset(pl, 0, sizeof(struct patchlist));
}

void patchlist_push(struct patchlist* pl) {
    pl->count = pl->count + 1;
    verify(pl->count < 16);
}

struct patch* patchlist_back(struct patchlist* pl) {
    return &(pl->entries[pl->count - 1]);
}

struct output {
    int fd;
    struct buffer data;
    struct constbytetable constbytes;
    struct patchlist patches;
};

void output_init(struct output* o, int fd) {
    o->fd = fd;
    buffer_init(&(o->data));
    constbytetable_init(&(o->constbytes));
    patchlist_init(&(o->patches));
}

int output_get_const_byte_data_offset(struct output* o, char value) {
    int index = value;
    int data_offset = o->constbytes.indexes[index];
    if (o->constbytes.indexes[index] == -1) {
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
int match_string(struct stream* s, char* expected) {
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
int match_string_with_spacing(struct stream* s, char* expected) {
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
int match_word(struct stream* s, char* expected) {
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
    return match_word(s, "char") || match_word(s, "int");
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

void* xmalloc(size_t bytes) {
    void* allocated = malloc(bytes);
    verify(allocated != 0);
    return allocated;
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
    char* id = xmalloc(len + 1);
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
*/
char* read_direct_declarator(struct stream* s) {
    char* name = read_identifier(s);
    if (!name) {
        return 0;
    }

    off_t pos = stream_tell(s);

    if (!match_string_with_spacing(s, "(")) {
        stream_seek(s, pos);
        return name;
    }

    if (!match_string_with_spacing(s, ")")) {
        fail_expected(s, "')'");

        stream_seek(s, pos);        
        return name;
    }

    return name;
}

/*
    N2176: 6.7.6 declarator:
        delarator <- pointer? direct-declarator

    Implemented:
        declarator <- direct_declarator

    Examples:
        main()
        main ( )
*/
char* read_declarator(struct stream* s) {
    return read_direct_declarator(s);
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
    verify(chararg->type == vt_char_constant);

    char opcode_out = 1;
    int wrote = write(prog_out->fd, &opcode_out, 1);
    verify(wrote == 1);
    
    int data_offset = output_get_const_byte_data_offset(prog_out, chararg->char_constant);

    int placeholder_pos = lseek(prog_out->fd, 0, SEEK_CUR);
    verify(placeholder_pos != -1);

    // write data pointer:
    char placeholder = 0;
    int i = 0;
    while (i < 4) {
        wrote = write(prog_out->fd, &placeholder, 1);
        verify(wrote == 1);
        i = i + 1;
    }

    patchlist_push(&prog_out->patches);
    struct patch* addrpatch = patchlist_back(&prog_out->patches);
    addrpatch->offset = data_offset;
    addrpatch->target = placeholder_pos;

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

void note_processed_as(struct stream* s, off_t pos, char* what) {
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
        if (!process_assignment_expression(s, val_out, prog_out)) {
            note_processed_as(s, pos, "assignment operator");
            fail_expected(s, "assignment expression after assignement operator");
            stream_seek(s, pos);
        }
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
*/
char* read_init_declarator(struct stream* s) {
    return read_declarator(s);
}


/*
    N2176: 6.7 init-declarator-list:
        init-declarator-list <- init-declarator / init-declarator-list COMMA init-declarator

    Implemented:
        init-declarator-list <- init_declarator

    Examples:
        main()
        main ( )
*/
char* match_init_declarator_list(struct stream* s) {
    return read_init_declarator(s);
}


/*
    N2176: 6.7 declaration:
        declaration <- declaration-specifiers init-declarator-list? SEMI / static_assert-declaration

    Implemented:
        declaration <- declaration_specifiers init-declarator-list SEMI

    Examples:
        char foo();
        int main();

*/
int match_declaration(struct stream* s) {
    off_t pos = stream_tell(s);

    if (!match_declaration_specifiers(s)) {
        return 0;
    }

    if (!match_init_declarator_list(s)) {
        stream_seek(s, pos);
        return 0;
    }

    if (!match_string_with_spacing(s, ";")) {
        stream_seek(s, pos);
        return 0;
    }

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
        cont = match_declaration(s)
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
        char getdirsep() { abort(); }
        int main() {}
        int main() { putchar('H'); putchar('\n'); }
        int main() { ;;;; }
*/
int match_function_definition(struct stream* s, struct output* prog_out) {
    off_t pos = stream_tell(s);
    if (!match_declaration_specifiers(s)) {
        return 0;
    }

    char* funcname = read_declarator(s);
    if (!funcname) {
        stream_seek(s, pos);
        dump_not_hint(s, __func__);
        return 0;
    }

    if (!match_compound_statement(s, prog_out)) {
        stream_seek(s, pos);
        return 0;
    }

    verify(strcmp(funcname, "main") == 0);

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
        int main() { ;;;; }
*/
int match_external_declaration(struct stream* s, struct output* prog_out) {
    return match_function_definition(s, prog_out) || match_declaration(s);
}

/*
    N2176: 6.9 translation-unit:
        translation-unit <- external-declaration / translation-unit external-declaration

    Implemented:
        translation_unit <- spacing external-declaration*

    Examples:
        int main() {}
        int main() { putchar('H'); } char unused() { abort(); } 
*/
void process_translation_unit(struct stream* s, struct output* prog_out) {
    count_spacing(s);

    while (match_external_declaration(s, prog_out)) {
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
