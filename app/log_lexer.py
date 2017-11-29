from pygments.lexer import RegexLexer, bygroups
from pygments.token import *


class FsoLogLexer(RegexLexer):
    name = 'FSO Debug Log'

    tokens = {
        'root': [
            (r'\-mod.*', Comment),
            (r'={3,}.*', Comment),
            (r'(FreeSpace 2 Open version: )(.*)$', bygroups(Text, Literal)),
            (r'(Passed cmdline options:|Building file index\.\.\.|FS2_Open Mission Log \- Opened)', Generic.Emph),
            (r'Variables:', Generic.Emph),
            (r'Setting language to [^\s]+', Generic.Emph),
            (r'(GL_ARB_texture_compression|GL_EXT_texture_compression_s3tc)', Generic.Emph),
            (r'^[A-Z ]+=>', Generic.Subheading),
            (r'Max texture size:', Generic.Emph),
            (r'Using extension', Generic.Emph),
            (r'(Potential problem found:|null moment of inertia|Turret object not found for turret firing point in model)', Generic.Warning),
            (r'(ALWAYS )?TRUE', Generic.Inserted),
            (r'(ALWAYS )?FALSE', Generic.Deleted),
            (r'(GS_[^ ]+)( \([0-9]+\))', bygroups(Keyword.Constant, Keyword.Constant)),
            (r'(Warning|Error)(: |!)', Generic.Emph),
            (r'[Ii]nvalid', Generic.Emph),
            (r'(Int3\(\)|ASSERTION)', Generic.Emph),
            (r'(Initializing|Compiling)', Generic.Emph),
            (r'\s', Whitespace),
            (r'.', Text)
        ]
    }
