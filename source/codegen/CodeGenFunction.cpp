//------------------------------------------------------------------------------
// CodeGenFunction.cpp
// LLVM code generation for SystemVerilog procedures
//
// File is under the MIT license; see LICENSE for details
//------------------------------------------------------------------------------
#include "CodeGenFunction.h"

#include "CodeGenTypes.h"

#include "slang/codegen/CodeGenerator.h"
#include "slang/mir/Procedure.h"
#include "slang/symbols/AllTypes.h"

namespace slang {

using namespace mir;

CodeGenFunction::CodeGenFunction(CodeGenerator& codegen, const Procedure& proc) :
    codegen(codegen), types(codegen.getTypes()), builder(codegen.getContext()),
    ctx(codegen.getContext()) {

    // Create the function object itself.
    auto funcType = llvm::FunctionType::get(types.VoidType, /* isVarArg */ false);
    generatedFunc =
        llvm::Function::Create(funcType, llvm::Function::PrivateLinkage, "", codegen.getModule());

    // Create the entry point basic block.
    auto bb = llvm::BasicBlock::Create(ctx, "entry", generatedFunc);

    // Create a marker to make it easy to insert allocas into the entryblock
    // later. Don't create this with the builder, because we don't want it folded.
    auto undef = llvm::UndefValue::get(types.Int32Type);
    allocaInsertionPoint = new llvm::BitCastInst(undef, types.Int32Type, "allocapt", bb);

    // Start emitting instructions.
    builder.SetInsertPoint(bb);
    for (auto& instr : proc.getInstructions())
        emit(instr);

    // All done!
    builder.CreateRetVoid();
}

llvm::Function* CodeGenFunction::finalize() {
    // Remove the alloca insertion point instruction, which is just a convenience for us.
    llvm::Instruction* ptr = std::exchange(allocaInsertionPoint, nullptr);
    ptr->eraseFromParent();

    return generatedFunc;
}

llvm::Value* CodeGenFunction::emit(const Instr& instr) {
    switch (instr.kind) {
        case InstrKind::syscall:
            return emitSysCall(instr.getSysCallKind(), instr.getOperands());
        case InstrKind::invalid:
            return builder.CreateUnreachable();
    }
    THROW_UNREACHABLE;
}

llvm::Value* CodeGenFunction::emit(MIRValue val) {
    switch (val.getKind()) {
        case MIRValue::Constant: {
            auto& tcv = val.asConstant();
            return emitConstant(tcv.type, tcv.value);
        }
        case MIRValue::InstrSlot:
        case MIRValue::Global:
        case MIRValue::Local:
        case MIRValue::Empty:
            // TODO:
            break;
    }
    THROW_UNREACHABLE;
}

llvm::Constant* CodeGenFunction::emitConstant(const Type& type, const ConstantValue& cv) {
    // TODO: other value types
    return emitConstant(type, cv.integer());
}

llvm::Constant* CodeGenFunction::emitConstant(const Type& type, const SVInt& integer) {
    auto& intType = type.as<IntegralType>();
    uint32_t bits = intType.bitWidth;
    if (intType.isFourState)
        bits *= 2;

    llvm::ArrayRef<uint64_t> data(integer.getRawPtr(), integer.getNumWords());
    if (bits <= codegen.getOptions().maxIntBits)
        return llvm::ConstantInt::get(ctx, llvm::APInt(bits, data));
    else
        return llvm::ConstantDataArray::get(ctx, data);
}

const Type& CodeGenFunction::getTypeOf(MIRValue val) const {
    switch (val.getKind()) {
        case MIRValue::Constant:
            return val.asConstant().type;
        case MIRValue::InstrSlot:
        case MIRValue::Global:
        case MIRValue::Local:
        case MIRValue::Empty:
            // TODO:
            break;
    }
    THROW_UNREACHABLE;
}

Address CodeGenFunction::createTempAlloca(llvm::Type* type, llvm::Align align) {
    auto inst = new llvm::AllocaInst(type, codegen.getModule().getDataLayout().getAllocaAddrSpace(),
                                     nullptr, align, "", allocaInsertionPoint);
    return Address(inst, align);
}

Address CodeGenFunction::boxInt(llvm::Value* value, const Type& type) {
    // TODO: put alignment behind an ABI
    auto addr = createTempAlloca(types.BoxedIntType, llvm::Align::Constant<8>());

    // TODO: fix int types
    bitwidth_t bits = type.getBitWidth();
    bool isSigned = type.isSigned();
    if (bits < 64) {
        if (isSigned)
            value = builder.CreateSExt(value, types.Int64Type);
        else
            value = builder.CreateZExt(value, types.Int64Type);
    }

    builder.CreateStore(value, builder.CreateStructGEP(types.BoxedIntType, addr, 0));

    // This matches the packing of flags in SVInt.
    uint32_t sizeAndFlags = bits;
    if (isSigned)
        sizeAndFlags |= (1u << SVInt::BITWIDTH_BITS);

    builder.CreateStore(llvm::ConstantInt::get(types.Int32Type, sizeAndFlags),
                        builder.CreateStructGEP(types.BoxedIntType, addr, 1));

    return addr;
}

} // namespace slang