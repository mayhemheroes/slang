#pragma once

namespace slang {

struct Trivia;
class Token;
class Allocator;

// TODO:
// - string escape sequences
// - track errors
// - populate token
// - scan directives
// - numeric literals

class Lexer {
public:
    Lexer(const char* sourceBuffer, Allocator& pool);

    Token* Lex();

private:
    TokenKind LexToken(void** extraData);
    void ScanIdentifier();
    void ScanExponent();
    void ScanStringLiteral(void** extraData);
    void ScanUnsizedNumericLiteral(void** extraData);
    void ScanVectorLiteral(void** extraData);
    TokenKind ScanNumericLiteral(void** extraData);
    TokenKind ScanEscapeSequence(void** extraData);
    TokenKind ScanDollarSign(void** extraData);
    TokenKind ScanDirective(void** extraData);

    bool LexTrivia();
    bool ScanBlockComment();
    void ScanWhitespace();
    void ScanLineComment();

    // factory helper methods
    void AddTrivia(TriviaKind kind);
    void AddError(DiagCode code);

    // source pointer manipulation
    void Mark() { marker = sourceBuffer; }
    void Advance() { sourceBuffer++; }
    void Advance(int count) { sourceBuffer += count; }
    void Back() { sourceBuffer--; }
    char Next() { return *sourceBuffer++; }
    char Peek() { return *sourceBuffer; }
    char Peek(int offset) { return sourceBuffer[offset]; }

    uint32_t GetCurrentLexemeLength() { return (uint32_t)(sourceBuffer - marker); }
    StringRef GetCurrentLexeme() { return StringRef(marker, GetCurrentLexemeLength()); }
    
    bool Consume(char c) {
        if (Peek() == c) {
            Advance();
            return true;
        }
        return false;
    }

    enum class LexingMode {
        Normal,
        Include,
        MacroDefine,
        OtherDirective
    };

    std::vector<Trivia> triviaBuffer;
    std::string stringBuilder;
    Allocator& pool;
    const char* sourceBuffer;
    const char* marker;
    LexingMode mode;
};

}