//------------------------------------------------------------------------------
//! @file LiteralExpressions.h
//! @brief Definitions for literal expressions
//
// SPDX-FileCopyrightText: Michael Popoloski
// SPDX-License-Identifier: MIT
//------------------------------------------------------------------------------
#pragma once

#include "slang/ast/Expression.h"
#include "slang/syntax/SyntaxFwd.h"

namespace slang::ast {

/// Represents an integer literal.
class SLANG_EXPORT IntegerLiteral : public Expression {
public:
    /// Indicates whether the original token in the source text was declared
    /// unsized; if false, an explicit size was given.
    bool isDeclaredUnsized;

    IntegerLiteral(BumpAllocator& alloc, const Type& type, const SVInt& value,
                   bool isDeclaredUnsized, SourceRange sourceRange);

    SVInt getValue() const { return valueStorage; }

    ConstantValue evalImpl(EvalContext& context) const;
    std::optional<bitwidth_t> getEffectiveWidthImpl() const;

    void serializeTo(ASTSerializer&) const;

    static Expression& fromSyntax(Compilation& compilation,
                                  const syntax::LiteralExpressionSyntax& syntax);
    static Expression& fromSyntax(Compilation& compilation,
                                  const syntax::IntegerVectorExpressionSyntax& syntax);
    static Expression& fromConstant(Compilation& compilation, const SVInt& value);

    static bool isKind(ExpressionKind kind) { return kind == ExpressionKind::IntegerLiteral; }

private:
    SVIntStorage valueStorage;
};

/// Represents a real number literal.
class SLANG_EXPORT RealLiteral : public Expression {
public:
    RealLiteral(const Type& type, double value, SourceRange sourceRange) :
        Expression(ExpressionKind::RealLiteral, type, sourceRange), value(value) {}

    double getValue() const { return value; }

    ConstantValue evalImpl(EvalContext& context) const;

    void serializeTo(ASTSerializer&) const;

    static Expression& fromSyntax(Compilation& compilation,
                                  const syntax::LiteralExpressionSyntax& syntax);

    static bool isKind(ExpressionKind kind) { return kind == ExpressionKind::RealLiteral; }

private:
    double value;
};

/// Represents a time literal.
class SLANG_EXPORT TimeLiteral : public Expression {
public:
    TimeLiteral(const Type& type, double value, SourceRange sourceRange) :
        Expression(ExpressionKind::TimeLiteral, type, sourceRange), value(value) {}

    double getValue() const { return value; }

    ConstantValue evalImpl(EvalContext& context) const;

    void serializeTo(ASTSerializer&) const;

    static Expression& fromSyntax(const ASTContext& context,
                                  const syntax::LiteralExpressionSyntax& syntax);

    static bool isKind(ExpressionKind kind) { return kind == ExpressionKind::TimeLiteral; }

private:
    double value;
};

/// Represents an unbased unsized integer literal, which fills all bits in an expression.
class SLANG_EXPORT UnbasedUnsizedIntegerLiteral : public Expression {
public:
    UnbasedUnsizedIntegerLiteral(const Type& type, logic_t value, SourceRange sourceRange) :
        Expression(ExpressionKind::UnbasedUnsizedIntegerLiteral, type, sourceRange), value(value) {}

    logic_t getLiteralValue() const { return value; }
    SVInt getValue() const;

    ConstantValue evalImpl(EvalContext& context) const;
    bool propagateType(const ASTContext& context, const Type& newType);
    std::optional<bitwidth_t> getEffectiveWidthImpl() const;

    void serializeTo(ASTSerializer&) const;

    static Expression& fromSyntax(Compilation& compilation,
                                  const syntax::LiteralExpressionSyntax& syntax);

    static bool isKind(ExpressionKind kind) {
        return kind == ExpressionKind::UnbasedUnsizedIntegerLiteral;
    }

private:
    logic_t value;
};

/// Represents a null literal.
class SLANG_EXPORT NullLiteral : public Expression {
public:
    NullLiteral(const Type& type, SourceRange sourceRange) :
        Expression(ExpressionKind::NullLiteral, type, sourceRange) {}

    ConstantValue evalImpl(EvalContext& context) const;

    void serializeTo(ASTSerializer&) const {}

    static Expression& fromSyntax(Compilation& compilation,
                                  const syntax::LiteralExpressionSyntax& syntax);

    static bool isKind(ExpressionKind kind) { return kind == ExpressionKind::NullLiteral; }
};

/// Represents the unboudned queue or range literal.
class SLANG_EXPORT UnboundedLiteral : public Expression {
public:
    UnboundedLiteral(const Type& type, SourceRange sourceRange) :
        Expression(ExpressionKind::UnboundedLiteral, type, sourceRange) {}

    ConstantValue evalImpl(EvalContext& context) const;

    void serializeTo(ASTSerializer&) const {}

    static Expression& fromSyntax(const ASTContext& context,
                                  const syntax::LiteralExpressionSyntax& syntax);

    static bool isKind(ExpressionKind kind) { return kind == ExpressionKind::UnboundedLiteral; }
};

/// Represents a string literal.
class SLANG_EXPORT StringLiteral : public Expression {
public:
    StringLiteral(const Type& type, string_view value, string_view rawValue, ConstantValue& intVal,
                  SourceRange sourceRange);

    string_view getValue() const { return value; }
    string_view getRawValue() const { return rawValue; }
    const ConstantValue& getIntValue() const;

    ConstantValue evalImpl(EvalContext& context) const;

    void serializeTo(ASTSerializer& serializer) const;

    static Expression& fromSyntax(const ASTContext& context,
                                  const syntax::LiteralExpressionSyntax& syntax);

    static bool isKind(ExpressionKind kind) { return kind == ExpressionKind::StringLiteral; }

private:
    string_view value;
    string_view rawValue;
    ConstantValue* intStorage;
};

} // namespace slang::ast
