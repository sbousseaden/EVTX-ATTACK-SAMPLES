#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import absolute_import

import re
import base64
import itertools

import six
import hexdump

from .BinaryParser import Block
from .BinaryParser import ParseException
from .BinaryParser import memoize


class SYSTEM_TOKENS:
    EndOfStreamToken = 0x00
    OpenStartElementToken = 0x01
    CloseStartElementToken = 0x02
    CloseEmptyElementToken = 0x03
    CloseElementToken = 0x04
    ValueToken = 0x05
    AttributeToken = 0x06
    CDataSectionToken = 0x07
    EntityReferenceToken = 0x08
    ProcessingInstructionTargetToken = 0x0A
    ProcessingInstructionDataToken = 0x0B
    TemplateInstanceToken = 0x0C
    NormalSubstitutionToken = 0x0D
    ConditionalSubstitutionToken = 0x0E
    StartOfStreamToken = 0x0F


class NODE_TYPES:
    NULL = 0x00
    WSTRING = 0x01
    STRING = 0x02
    SIGNED_BYTE = 0x03
    UNSIGNED_BYTE = 0x04
    SIGNED_WORD = 0x05
    UNSIGNED_WORD = 0x06
    SIGNED_DWORD = 0x07
    UNSIGNED_DWORD = 0x08
    SIGNED_QWORD = 0x09
    UNSIGNED_QWORD = 0x0A
    FLOAT = 0x0B
    DOUBLE = 0x0C
    BOOLEAN = 0x0D
    BINARY = 0x0E
    GUID = 0x0F
    SIZE = 0x10
    FILETIME = 0x11
    SYSTEMTIME = 0x12
    SID = 0x13
    HEX32 = 0x14
    HEX64 = 0x15
    BXML = 0x21
    WSTRINGARRAY = 0x81


node_dispatch_table = []  # updated at end of file
node_readable_tokens = []  # updated at end of file


class SuppressConditionalSubstitution(Exception):
    """
    This exception is to be thrown to indicate that a conditional
      substitution evaluated to NULL, and the parent element should
      be suppressed. This exception should be caught at the first
      opportunity, and must not propagate far up the call chain.

    Strategy:
      AttributeNode catches this, .xml() --> ""
      StartOpenElementNode catches this for each child, ensures
        there's at least one useful value.  Or, .xml() --> ""
    """
    def __init__(self, msg):
        super(SuppressConditionalSubstitution, self).__init__(msg)


class UnexpectedStateException(ParseException):
    """
    UnexpectedStateException is an exception to be thrown when the parser
      encounters an unexpected value or state. This probably means there
      is a bug in the parser, but could stem from a corrupted input file.
    """
    def __init__(self, msg):
        super(UnexpectedStateException, self).__init__(msg)


class BXmlNode(Block):

    def __init__(self, buf, offset, chunk, parent):
        super(BXmlNode, self).__init__(buf, offset)
        self._chunk = chunk
        self._parent = parent

    def __repr__(self):
        return "BXmlNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "BXmlNode(offset={})".format(hex(self.offset()))

    def dump(self):
        b = self._buf[self.offset():self.offset() + self.length()]
        return hexdump.hexdump(b, result='return')

    def tag_length(self):
        """
        This method must be implemented and overridden for all BXmlNodes.
        @return An integer specifying the length of this tag, not including
          its children.
        """
        raise NotImplementedError("tag_length not implemented for {!r}").format(self)

    def _children(self, max_children=None,
                  end_tokens=[SYSTEM_TOKENS.EndOfStreamToken]):
        """
        @return A list containing all of the children BXmlNodes.
        """
        ret = []
        ofs = self.tag_length()

        if max_children:
            gen = list(range(max_children))
        else:
            gen = itertools.count()

        for _ in gen:
            # we lose error checking by masking off the higher nibble,
            #   but, some tokens like 0x01, make use of the flags nibble.
            token = self.unpack_byte(ofs) & 0x0F
            try:
                HandlerNodeClass = node_dispatch_table[token]
                child = HandlerNodeClass(self._buf, self.offset() + ofs,
                                         self._chunk, self)
            except IndexError:
                raise ParseException("Unexpected token {:02X} at {}".format(
                    token,
                    self.absolute_offset(0x0) + ofs))
            ret.append(child)
            ofs += child.length()
            if token in end_tokens:
                break
            if child.find_end_of_stream():
                break
        return ret

    @memoize
    def children(self):
        return self._children()

    @memoize
    def length(self):
        """
        @return An integer specifying the length of this tag and all
          its children.
        """
        ret = self.tag_length()
        for child in self.children():
            ret += child.length()
        return ret

    @memoize
    def find_end_of_stream(self):
        for child in self.children():
            if isinstance(child, EndOfStreamNode):
                return child
            ret = child.find_end_of_stream()
            if ret:
                return ret
        return None


class NameStringNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        super(NameStringNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("word", "hash")
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "string", length=self.string_length())

    def __repr__(self):
        return "NameStringNode(buf={!r}, offset={!r}, chunk={!r})".format(
            self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "NameStringNode(offset={}, length={}, end={})".format(
            hex(self.offset()), hex(self.length()),
            hex(self.offset() + self.length()))

    def string(self):
        return str(self._string())

    def tag_length(self):
        return (self.string_length() * 2) + 8

    def length(self):
        # two bytes unaccounted for...
        return self.tag_length() + 2


class TemplateNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        super(TemplateNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("dword", "template_id")
        self.declare_field("guid",  "guid", 0x04)  # unsure why this overlaps
        self.declare_field("dword", "data_length")

    def __repr__(self):
        return "TemplateNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "TemplateNode(offset={}, guid={}, length={})".format(
            hex(self.offset()), self.guid(), hex(self.length()))

    def tag_length(self):
        return 0x18

    def length(self):
        return self.tag_length() + self.data_length()


class EndOfStreamNode(BXmlNode):
    """
    The binary XML node for the system token 0x00.

    This is the "end of stream" token. It may never actually
      be instantiated here.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(EndOfStreamNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "EndOfStreamNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "EndOfStreamNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), 0x00)

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []


class OpenStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x01.

    This is the "open start element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(OpenStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "unknown0")
        # TODO(wb): use this size() field.
        self.declare_field("dword", "size")
        self.declare_field("dword", "string_offset")
        self._tag_length = 11
        self._element_type = 0

        if self.flags() & 0x04:
            self._tag_length += 4

        if self.string_offset() > self.offset() - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "OpenStartElementNode(buf={!r}, offset={!r}, chunk={!r})".format(
            self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "OpenStartElementNode(offset={}, name={}, length={}, token={}, end={}, taglength={}, endtag={})".format(
            hex(self.offset()), self.tag_name(),
            hex(self.length()), hex(self.token()),
            hex(self.offset() + self.length()),
            hex(self.tag_length()),
            hex(self.offset() + self.tag_length()))

    @memoize
    def is_empty_node(self):
        for child in self.children():
            if type(child) is CloseEmptyElementNode:
                return True
        return False

    def flags(self):
        return self.token() >> 4

    @memoize
    def tag_name(self):
        return self._chunk.strings()[self.string_offset()].string()

    def tag_length(self):
        return self._tag_length

    def verify(self):
        return self.flags() & 0x0b == 0 and \
            self.opcode() & 0x0F == 0x01

    @memoize
    def children(self):
        return self._children(end_tokens=[SYSTEM_TOKENS.CloseElementToken,
                                          SYSTEM_TOKENS.CloseEmptyElementToken])


class CloseStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x02.

    This is the "close start element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CloseStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseStartElementNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseStartElementNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()))

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []

    def verify(self):
        return self.flags() & 0x0F == 0 and \
            self.opcode() & 0x0F == 0x02


class CloseEmptyElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x03.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CloseEmptyElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseEmptyElementNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseEmptyElementNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x03))

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []


class CloseElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x04.

    This is the "close element" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CloseElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseElementNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CloseElementNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()))

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 1

    def length(self):
        return 1

    def children(self):
        return []

    def verify(self):
        return self.flags() & 0x0F == 0 and \
            self.opcode() & 0x0F == 0x04


def get_variant_value(buf, offset, chunk, parent, type_, length=None):
    """
    @return A VariantType subclass instance found in the given
      buffer and offset.
    """
    types = {
        NODE_TYPES.NULL: NullTypeNode,
        NODE_TYPES.WSTRING: WstringTypeNode,
        NODE_TYPES.STRING: StringTypeNode,
        NODE_TYPES.SIGNED_BYTE: SignedByteTypeNode,
        NODE_TYPES.UNSIGNED_BYTE: UnsignedByteTypeNode,
        NODE_TYPES.SIGNED_WORD: SignedWordTypeNode,
        NODE_TYPES.UNSIGNED_WORD: UnsignedWordTypeNode,
        NODE_TYPES.SIGNED_DWORD: SignedDwordTypeNode,
        NODE_TYPES.UNSIGNED_DWORD: UnsignedDwordTypeNode,
        NODE_TYPES.SIGNED_QWORD: SignedQwordTypeNode,
        NODE_TYPES.UNSIGNED_QWORD: UnsignedQwordTypeNode,
        NODE_TYPES.FLOAT: FloatTypeNode,
        NODE_TYPES.DOUBLE: DoubleTypeNode,
        NODE_TYPES.BOOLEAN: BooleanTypeNode,
        NODE_TYPES.BINARY: BinaryTypeNode,
        NODE_TYPES.GUID: GuidTypeNode,
        NODE_TYPES.SIZE: SizeTypeNode,
        NODE_TYPES.FILETIME: FiletimeTypeNode,
        NODE_TYPES.SYSTEMTIME: SystemtimeTypeNode,
        NODE_TYPES.SID: SIDTypeNode,
        NODE_TYPES.HEX32: Hex32TypeNode,
        NODE_TYPES.HEX64: Hex64TypeNode,
        NODE_TYPES.BXML: BXmlTypeNode,
        NODE_TYPES.WSTRINGARRAY: WstringArrayTypeNode,
    }
    try:
        TypeClass = types[type_]
    except IndexError:
        raise NotImplementedError("Type {} not implemented".format(type_))
    return TypeClass(buf, offset, chunk, parent, length=length)


class ValueNode(BXmlNode):
    """
    The binary XML node for the system token 0x05.

    This is the "value" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ValueNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "type")

    def __repr__(self):
        return "ValueNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ValueNode(offset={}, length={}, token={}, value={})".format(
            hex(self.offset()), hex(self.length()),
            hex(self.token()), self.value().string())

    def flags(self):
        return self.token() >> 4

    def value(self):
        return self.children()[0]

    def tag_length(self):
        return 2

    def children(self):
        child = get_variant_value(self._buf,
                                  self.offset() + self.tag_length(),
                                  self._chunk, self, self.type())
        return [child]

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.ValueToken


class AttributeNode(BXmlNode):
    """
    The binary XML node for the system token 0x06.

    This is the "attribute" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(AttributeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")

        self._name_string_length = 0
        if self.string_offset() > self.offset() - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._name_string_length += new_string.length()

    def __repr__(self):
        return "AttributeNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "AttributeNode(offset={}, length={}, token={}, name={}, value={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()),
            self.attribute_name(), self.attribute_value())

    def flags(self):
        return self.token() >> 4

    def attribute_name(self):
        """
        @return A NameNode instance that contains the attribute name.
        """
        return self._chunk.strings()[self.string_offset()]

    def attribute_value(self):
        """
        @return A BXmlNode instance that is one of (ValueNode,
          ConditionalSubstitutionNode, NormalSubstitutionNode).
        """
        return self.children()[0]

    def tag_length(self):
        return 5 + self._name_string_length

    def verify(self):
        return self.flags() & 0x0B == 0 and \
            self.opcode() & 0x0F == 0x06

    @memoize
    def children(self):
        return self._children(max_children=1)


class CDataSectionNode(BXmlNode):
    """
    The binary XML node for the system token 0x07.

    This is the "CDATA section" system token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CDataSectionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "cdata", length=self.string_length() - 2)

    def __repr__(self):
        return "CDataSectionNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CDataSectionNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), 0x07)

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 0x3 + self.string_length()

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.CDataSectionToken


class CharacterReferenceNode(BXmlNode):
    """
    The binary XML node for the system token 0x08.

    This is an character reference node.  That is, something that represents
      a non-XML character, eg. & --> &#x0038;.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(CharacterReferenceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "entity")
        self._tag_length = 3

    def __repr__(self):
        return "CharacterReferenceNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "CharacterReferenceNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x08))

    def entity_reference(self):
        return '&#x%04x;' % (self.entity())

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return self._tag_length

    def children(self):
        return []


class EntityReferenceNode(BXmlNode):
    """
    The binary XML node for the system token 0x09.

    This is an entity reference node.  That is, something that represents
      a non-XML character, eg. & --> &amp;.

    TODO(wb): this is untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(EntityReferenceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "EntityReferenceNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "EntityReferenceNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x09))

    def entity_reference(self):
        return "&{};".format(self._chunk.strings()[self.string_offset()].string())

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []


class ProcessingInstructionTargetNode(BXmlNode):
    """
    The binary XML node for the system token 0x0A.

    TODO(wb): untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ProcessingInstructionTargetNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(),
                                                parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "ProcessingInstructionTargetNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ProcessingInstructionTargetNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0A))

    def processing_instruction_target(self):
        return "<?{}".format(self._chunk.strings()[self.string_offset()].string())

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []


class ProcessingInstructionDataNode(BXmlNode):
    """
    The binary XML node for the system token 0x0B.

    TODO(wb): untested.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ProcessingInstructionDataNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self._tag_length = 3 + (2 * self.string_length())

        if self.string_length() > 0:
            self._string = self.unpack_wstring(0x3, self.string_length())
        else:
            self._string = ""

    def __repr__(self):
        return "ProcessingInstructionDataNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ProcessingInstructionDataNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0B))

    def flags(self):
        return self.token() >> 4

    def string(self):
        if self.string_length() > 0:
            return " {}?>".format(self._string)
        else:
            return "?>"

    def tag_length(self):
        return self._tag_length

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        return []


class TemplateInstanceNode(BXmlNode):
    """
    The binary XML node for the system token 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(TemplateInstanceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("dword", "template_id")
        self.declare_field("dword", "template_offset")

        self._data_length = 0

        if self.is_resident_template():
            new_template = self._chunk.add_template(self.template_offset(),
                                                    parent=self)
            self._data_length += new_template.length()

    def __repr__(self):
        return "TemplateInstanceNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "TemplateInstanceNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0C))

    def flags(self):
        return self.token() >> 4

    def is_resident_template(self):
        return self.template_offset() > self.offset() - self._chunk._offset

    def tag_length(self):
        return 10

    def length(self):
        return self.tag_length() + self._data_length

    def template(self):
        return self._chunk.templates()[self.template_offset()]

    def children(self):
        return []

    @memoize
    def find_end_of_stream(self):
        return self.template().find_end_of_stream()


class NormalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0D.

    This is a "normal substitution" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(NormalSubstitutionNode, self).__init__(buf, offset,
                                                     chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

    def __repr__(self):
        return "NormalSubstitutionNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "NormalSubstitutionNode(offset={}, length={}, token={}, index={}, type={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()),
            self.index(), self.type())

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 0x4

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.NormalSubstitutionToken


class ConditionalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0E.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(ConditionalSubstitutionNode, self).__init__(buf, offset,
                                                          chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

    def __repr__(self):
        return "ConditionalSubstitutionNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "ConditionalSubstitutionNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0E))

    def should_suppress(self, substitutions):
        sub = substitutions[self.index()]
        return type(sub) is NullTypeNode

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 0x4

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def verify(self):
        return self.flags() == 0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.ConditionalSubstitutionToken


class StreamStartNode(BXmlNode):
    """
    The binary XML node for the system token 0x0F.

    This is the "start of stream" token.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(StreamStartNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("word", "unknown1")

    def __repr__(self):
        return "StreamStartNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "StreamStartNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()))

    def verify(self):
        return self.flags() == 0x0 and \
            self.token() & 0x0F == SYSTEM_TOKENS.StartOfStreamToken and \
            self.unknown0() == 0x1 and \
            self.unknown1() == 0x1

    def flags(self):
        return self.token() >> 4

    def tag_length(self):
        return 4

    def length(self):
        return self.tag_length() + 0

    def children(self):
        return []


class RootNode(BXmlNode):
    """
    The binary XML node for the Root node.
    """
    def __init__(self, buf, offset, chunk, parent):
        super(RootNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "RootNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent)

    def __str__(self):
        return "RootNode(offset={}, length={})".format(
            hex(self.offset()), hex(self.length()))

    def tag_length(self):
        return 0

    @memoize
    def children(self):
        """
        @return The template instances which make up this node.
        """
        return self._children(end_tokens=[SYSTEM_TOKENS.EndOfStreamToken])

    def tag_and_children_length(self):
        """
        @return The length of the tag of this element, and the children.
          This does not take into account the substitutions that may be
          at the end of this element.
        """
        children_length = 0

        for child in self.children():
            children_length += child.length()

        return self.tag_length() + children_length

    def template_instance(self):
        '''
        parse the template instance node.
        this is used to compute the location of the template definition structure.

        Returns:
          TemplateInstanceNode: the template instance.
        '''
        ofs = self.offset()
        if self.unpack_byte(0x0) & 0x0F == 0xF:
            ofs += 4
        return TemplateInstanceNode(self._buf, ofs, self._chunk, self)

    def template(self):
        '''
        parse the template referenced by this root node.
        note, this template structure is not guaranteed to be located within the root node's boundaries.

        Returns:
          TemplateNode: the template.
        '''
        instance = self.template_instance()
        offset = self._chunk.offset() + instance.template_offset()
        node = TemplateNode(self._buf, offset, self._chunk, instance)
        return node

    @memoize
    def substitutions(self):
        """
        @return A list of VariantTypeNode subclass instances that
          contain the substitutions for this root node.
        """
        sub_decl = []
        sub_def = []
        ofs = self.tag_and_children_length()
        sub_count = self.unpack_dword(ofs)
        ofs += 4
        for _ in range(sub_count):
            size = self.unpack_word(ofs)
            type_ = self.unpack_byte(ofs + 0x2)
            sub_decl.append((size, type_))
            ofs += 4
        for (size, type_) in sub_decl:
            val = get_variant_value(self._buf, self.offset() + ofs,
                                    self._chunk, self, type_, length=size)
            if abs(size - val.length()) > 4:
                # TODO(wb): This is a hack, so I'm sorry.
                #   But, we are not passing around a 'length' field,
                #   so we have to depend on the structure of each
                #   variant type.  It seems some BXmlTypeNode sizes
                #   are not exact.  Hopefully, this is just alignment.
                #   So, that's what we compensate for here.
                raise ParseException("Invalid substitution value size")
            sub_def.append(val)
            ofs += size
        return sub_def

    @memoize
    def length(self):
        ofs = self.tag_and_children_length()
        sub_count = self.unpack_dword(ofs)
        ofs += 4
        ret = ofs
        for _ in range(sub_count):
            size = self.unpack_word(ofs)
            ret += size + 4
            ofs += 4
        return ret


class VariantTypeNode(BXmlNode):
    """

    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(VariantTypeNode, self).__init__(buf, offset, chunk, parent)
        self._length = length

    def __repr__(self):
        return "{}(buf={!r}, offset={}, chunk={!r})".format(
            self.__class__.__name__, self._buf, hex(self.offset()),
            self._chunk)

    def __str__(self):
        return "{}(offset={}, length={}, string={})".format(
            self.__class__.__name__, hex(self.offset()),
            hex(self.length()), self.string())

    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for {!r}".format(self))

    def length(self):
        return self.tag_length()

    def children(self):
        return []

    def string(self):
        raise NotImplementedError("string not implemented for {!r}".format(self))


# but satisfies the contract of VariantTypeNode, BXmlNode, but not Block
class NullTypeNode(object):
    """
    Variant type 0x00.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(NullTypeNode, self).__init__()
        self._offset = offset
        self._length = length

    def __str__(self):
        return "NullTypeNode"

    def string(self):
        return ""

    def length(self):
        return self._length or 0

    def tag_length(self):
        return self._length or 0

    def children(self):
        return []

    def offset(self):
        return self._offset


class WstringTypeNode(VariantTypeNode):
    """
    Variant ttype 0x01.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(WstringTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        if self._length is None:
            self.declare_field("word",    "string_length", 0x0)
            self.declare_field("wstring", "_string",
                               length=(self.string_length()))
        else:
            self.declare_field("wstring", "_string", 0x0,
                               length=(self._length // 2))

    def tag_length(self):
        if self._length is None:
            return (2 + (self.string_length() * 2))
        return self._length

    def string(self):
        return self._string().rstrip("\x00")


class StringTypeNode(VariantTypeNode):
    """
    Variant type 0x02.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(StringTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        if self._length is None:
            self.declare_field("word",   "string_length", 0x0)
            self.declare_field("string", "_string",
                               length=(self.string_length()))
        else:
            self.declare_field("string", "_string", 0x0, length=self._length)

    def tag_length(self):
        if self._length is None:
            return (2 + (self.string_length()))
        return self._length

    def string(self):
        return self._string().rstrip("\x00")


class SignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x03.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedByteTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("int8", "byte", 0x0)

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class UnsignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x04.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedByteTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                   length=length)
        self.declare_field("byte", "byte", 0x0)

    def tag_length(self):
        return 1

    def string(self):
        return str(self.byte())


class SignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x05.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedWordTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("int16", "word", 0x0)

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class UnsignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x06.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedWordTypeNode, self).__init__(buf, offset,
                                                   chunk, parent,
                                                   length=length)
        self.declare_field("word", "word", 0x0)

    def tag_length(self):
        return 2

    def string(self):
        return str(self.word())


class SignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x07.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedDwordTypeNode, self).__init__(buf, offset, chunk,
                                                  parent, length=length)
        self.declare_field("int32", "dword", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class UnsignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x08.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedDwordTypeNode, self).__init__(buf, offset,
                                                    chunk, parent,
                                                    length=length)
        self.declare_field("dword", "dword", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        return str(self.dword())


class SignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x09.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedQwordTypeNode, self).__init__(buf, offset, chunk,
                                                  parent, length=length)
        self.declare_field("int64", "qword", 0x0)

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class UnsignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x0A.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedQwordTypeNode, self).__init__(buf, offset,
                                                    chunk, parent,
                                                    length=length)
        self.declare_field("qword", "qword", 0x0)

    def tag_length(self):
        return 8

    def string(self):
        return str(self.qword())


class FloatTypeNode(VariantTypeNode):
    """
    Variant type 0x0B.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(FloatTypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("float", "float", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        return str(self.float())


class DoubleTypeNode(VariantTypeNode):
    """
    Variant type 0x0C.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(DoubleTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        self.declare_field("double", "double", 0x0)

    def tag_length(self):
        return 8

    def string(self):
        return str(self.double())


class BooleanTypeNode(VariantTypeNode):
    """
    Variant type 0x0D.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BooleanTypeNode, self).__init__(buf, offset, chunk,
                                              parent, length=length)
        self.declare_field("int32", "int32", 0x0)

    def tag_length(self):
        return 4

    def string(self):
        if self.int32() > 0:
            return "True"
        return "False"


class BinaryTypeNode(VariantTypeNode):
    """
    Variant type 0x0E.

    String/XML representation is Base64 encoded.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BinaryTypeNode, self).__init__(buf, offset, chunk,
                                             parent, length=length)
        if self._length is None:
            self.declare_field("dword", "size", 0x0)
            self.declare_field("binary", "binary", length=self.size())
        else:
            self.declare_field("binary", "binary", 0x0, length=self._length)

    def tag_length(self):
        if self._length is None:
            return (4 + self.size())
        return self._length

    def string(self):
        return base64.b64encode(self.binary()).decode('ascii')


class GuidTypeNode(VariantTypeNode):
    """
    Variant type 0x0F.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(GuidTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        self.declare_field("guid", "guid", 0x0)

    def tag_length(self):
        return 16

    def string(self):
        return '{' + self.guid() + '}'


class SizeTypeNode(VariantTypeNode):
    """
    Variant type 0x10.

    Note: Assuming sizeof(size_t) == 0x8.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SizeTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        if self._length == 0x4:
            self.declare_field("dword", "num", 0x0)
        elif self._length == 0x8:
            self.declare_field("qword", "num", 0x0)
        else:
            self.declare_field("qword", "num", 0x0)

    def tag_length(self):
        if self._length is None:
            return 8
        return self._length

    def string(self):
        return str(self.num())


class FiletimeTypeNode(VariantTypeNode):
    """
    Variant type 0x11.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(FiletimeTypeNode, self).__init__(buf, offset, chunk,
                                               parent, length=length)
        self.declare_field("filetime", "filetime", 0x0)

    def string(self):
        return self.filetime().isoformat(' ')

    def tag_length(self):
        return 8


class SystemtimeTypeNode(VariantTypeNode):
    """
    Variant type 0x12.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SystemtimeTypeNode, self).__init__(buf, offset, chunk,
                                                 parent, length=length)
        self.declare_field("systemtime", "systemtime", 0x0)

    def tag_length(self):
        return 16

    def string(self):
        return self.systemtime().isoformat(' ')


class SIDTypeNode(VariantTypeNode):
    """
    Variant type 0x13.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SIDTypeNode, self).__init__(buf, offset, chunk,
                                          parent, length=length)
        self.declare_field("byte",  "version", 0x0)
        self.declare_field("byte",  "num_elements")
        self.declare_field("dword_be", "id_high")
        self.declare_field("word_be",  "id_low")

    @memoize
    def elements(self):
        ret = []
        for i in range(self.num_elements()):
            ret.append(self.unpack_dword(self.current_field_offset() + 4 * i))
        return ret

    @memoize
    def id(self):
        ret = "S-{}-{}".format(
            self.version(), (self.id_high() << 16) ^ self.id_low())
        for elem in self.elements():
            ret += "-{}".format(elem)
        return ret

    def tag_length(self):
        return 8 + 4 * self.num_elements()

    def string(self):
        return self.id()


class Hex32TypeNode(VariantTypeNode):
    """
    Variant type 0x14.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(Hex32TypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x4)

    def tag_length(self):
        return 4

    def string(self):
        ret = "0x"
        b = self.hex()[::-1]
        for i in range(len(b)):
            ret += '{:02x}'.format(six.indexbytes(b, i))
        return ret


class Hex64TypeNode(VariantTypeNode):
    """
    Variant type 0x15.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(Hex64TypeNode, self).__init__(buf, offset, chunk,
                                            parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x8)

    def tag_length(self):
        return 8

    def string(self):
        ret = "0x"
        b = self.hex()[::-1]
        for i in range(len(b)):
            ret += '{:02x}'.format(six.indexbytes(b, i))
        return ret


class BXmlTypeNode(VariantTypeNode):
    """
    Variant type 0x21.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BXmlTypeNode, self).__init__(buf, offset, chunk,
                                           parent, length=length)
        self._root = RootNode(buf, offset, chunk, self)

    def tag_length(self):
        return self._length or self._root.length()

    def string(self):
        return ''

    def root(self):
        return self._root


class WstringArrayTypeNode(VariantTypeNode):
    """
    Variant ttype 0x81.
    """
    def __init__(self, buf, offset, chunk, parent, length=None):
        super(WstringArrayTypeNode, self).__init__(buf, offset, chunk,
                                                   parent, length=length)
        if self._length is None:
            self.declare_field("word",   "binary_length", 0x0)
            self.declare_field("binary", "binary",
                               length=(self.binary_length()))
        else:
            self.declare_field("binary", "binary", 0x0,
                               length=(self._length))

    def tag_length(self):
        if self._length is None:
            return (2 + self.binary_length())
        return self._length

    def string(self):
        binary = self.binary()
        acc = []
        while len(binary) > 0:
            match = re.search(b"((?:[^\x00].)+)", binary)
            if match:
                frag = match.group()
                acc.append("<string>")
                acc.append(frag.decode("utf16"))
                acc.append("</string>\n")
                binary = binary[len(frag) + 2:]
                if len(binary) == 0:
                    break
            frag = re.search(b"(\x00*)", binary).group()
            if len(frag) % 2 == 0:
                for _ in range(len(frag) // 2):
                    acc.append("<string></string>\n")
            else:
                raise ParseException("Error parsing uneven substring of NULLs")
            binary = binary[len(frag):]
        return "".join(acc)


node_dispatch_table = [
    EndOfStreamNode,
    OpenStartElementNode,
    CloseStartElementNode,
    CloseEmptyElementNode,
    CloseElementNode,
    ValueNode,
    AttributeNode,
    CDataSectionNode,
    CharacterReferenceNode,
    EntityReferenceNode,
    ProcessingInstructionTargetNode,
    ProcessingInstructionDataNode,
    TemplateInstanceNode,
    NormalSubstitutionNode,
    ConditionalSubstitutionNode,
    StreamStartNode,
    ]

node_readable_tokens = [
    "End of Stream",
    "Open Start Element",
    "Close Start Element",
    "Close Empty Element",
    "Close Element",
    "Value",
    "Attribute",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "TemplateInstanceNode",
    "Normal Substitution",
    "Conditional Substitution",
    "Start of Stream",
    ]
