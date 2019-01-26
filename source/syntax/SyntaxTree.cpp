//------------------------------------------------------------------------------
// SyntaxTree.cpp
// Top-level parser interface.
//
// File is under the MIT license; see LICENSE for details.
//------------------------------------------------------------------------------
#include "slang/syntax/SyntaxTree.h"

#include "slang/parsing/Parser.h"
#include "slang/parsing/Preprocessor.h"
#include "slang/text/SourceManager.h"

namespace slang {

SyntaxTree::SyntaxTree(SyntaxNode* root, SourceManager& sourceManager, BumpAllocator&& alloc,
                       std::shared_ptr<SyntaxTree> parent) :
    rootNode(root),
    sourceMan(sourceManager), alloc(std::move(alloc)), parentTree(std::move(parent)) {
    if (parentTree)
        eof = parentTree->eof;
}

std::shared_ptr<SyntaxTree> SyntaxTree::fromFile(string_view path) {
    return fromFile(path, getDefaultSourceManager());
}

std::shared_ptr<SyntaxTree> SyntaxTree::fromText(string_view text, string_view name) {
    return fromText(text, getDefaultSourceManager(), name);
}

std::shared_ptr<SyntaxTree> SyntaxTree::fromFile(string_view path, SourceManager& sourceManager,
                                                 const Bag& options) {
    SourceBuffer buffer = sourceManager.readSource(path);
    if (!buffer)
        return nullptr;
    return create(sourceManager, buffer, options, false);
}

std::shared_ptr<SyntaxTree> SyntaxTree::fromText(string_view text, SourceManager& sourceManager,
                                                 string_view name, const Bag& options) {
    return create(sourceManager, sourceManager.assignText(name, text), options, true);
}

std::shared_ptr<SyntaxTree> SyntaxTree::fromBuffer(const SourceBuffer& buffer,
                                                   SourceManager& sourceManager,
                                                   const Bag& options) {
    return create(sourceManager, buffer, options, false);
}

SourceManager& SyntaxTree::getDefaultSourceManager() {
    static SourceManager instance;
    return instance;
}

SyntaxTree::SyntaxTree(SyntaxNode* root, SourceManager& sourceManager, BumpAllocator&& alloc,
                       Diagnostics&& diagnostics, Parser::MetadataMap&& metadataMap,
                       Bag options, Token eof) :
    rootNode(root),
    sourceMan(sourceManager), metadataMap(std::move(metadataMap)), alloc(std::move(alloc)),
    diagnosticsBuffer(std::move(diagnostics)), options_(std::move(options)), eof(eof) {
}

std::shared_ptr<SyntaxTree> SyntaxTree::create(SourceManager& sourceManager, SourceBuffer source,
                                               const Bag& options, bool guess) {
    BumpAllocator alloc;
    Diagnostics diagnostics;
    Preprocessor preprocessor(sourceManager, alloc, diagnostics, options);
    preprocessor.pushSource(source);

    Parser parser(preprocessor, options);

    SyntaxNode* root;
    if (!guess)
        root = &parser.parseCompilationUnit();
    else {
        root = &parser.parseGuess();
        if (!parser.isDone())
            return create(sourceManager, source, options, false);
    }

    return std::shared_ptr<SyntaxTree>(
        new SyntaxTree(root, sourceManager, std::move(alloc), std::move(diagnostics),
                       parser.getMetadataMap(), options, parser.getEOFToken()));
}

} // namespace slang
