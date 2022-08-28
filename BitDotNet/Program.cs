var sourceFileName = args[0].Replace("\"", string.Empty).Trim();

using (var stream = File.Open(sourceFileName, FileMode.Open, FileAccess.ReadWrite))
using (var reader = new BinaryReader(stream))
using (var writer = new BinaryWriter(stream))
{
    stream.Position = 0x3C;
    var peHeader = reader.ReadUInt32();
    stream.Position = peHeader;

    writer.Write(0x00014550); // BIT PE SIGNATURE

    stream.Position += 0x2;
    var numberOfSections = reader.ReadUInt16();

    stream.Position += 0x10;
    var is64PEOptionsHeader = reader.ReadUInt16() == 0x20B;

    stream.Position += is64PEOptionsHeader ? 0x38 : 0x28 + 0xA6;
    var dotNetVirtualAddress = reader.ReadUInt32();

    uint dotNetPointerRaw = 0;
    stream.Position += 0xC;
    for (int i = 0; i < numberOfSections; i++)
    {
        stream.Position += 0xC;
        var virtualAddress = reader.ReadUInt32();
        var sizeOfRawData = reader.ReadUInt32();
        var pointerToRawData = reader.ReadUInt32();
        stream.Position += 0x10;

        if (dotNetVirtualAddress >= virtualAddress && dotNetVirtualAddress < virtualAddress + sizeOfRawData && dotNetPointerRaw == 0)
        {
            dotNetPointerRaw = dotNetVirtualAddress + pointerToRawData - virtualAddress;
        }
    }

    stream.Position = dotNetPointerRaw;
    writer.Write(0); // BIT CB Bytes (breaks dnlib example: Dnspy)
    stream.Position += 0x8;
    writer.Write(0); // BIT Metadata size (breaks Mono.Cecil and maybe more :) examples: ILSpy, dotPeek)
}
