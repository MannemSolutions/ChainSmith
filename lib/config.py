from os import path

class ConfigFile(list):
    """
    configparser does not work with config without a section header. Everything should be 
    under a [ section ]. But openssl.cnf does have stuff which is not in any section (top).
    Furthermore, it als has values that are not formatted `key = value`, such as
       .include /etc/crypto-policies/back-ends/opensslcnf.config
    For these reasons we don;t use configparser, but rather parse the config ourselves.

    ConfigFile is the main placeholder for all config in a file.
    It is a list of config sections, where every config section is of type ConfigChapter.
    """

    def __init__(self, file):
        super().__init__()
        file = path.realpath(path.expanduser(file))
        chapter = ConfigChapter('')
        self.append(chapter)
        with open(file) as cf:
            for line in cf:
                line = line.strip()
                if len(line) == 0:
                    chapter.append(ConfigLine(line))
                elif line[0] == '[' and line[-1] == ']':
                    chapter = ConfigChapter(line[1:-2].strip())
                    self.append(chapter)
                else:
                    chapter.append(ConfigLine(line))

    def write(self, file):
        file = path.realpath(path.expanduser(file))
        try:
            with open(file, 'w') as cf:
                cf.write(self.string())
        except OSError as os_err:
            print('Cannot open file:', os_err)

    def string(self):
        return '\n'.join([cc.string() for cc in self])

    def set_chapter(self, new_chapter):
        for i in range(len(self)):
            chapter = self[i]
            if chapter.name() == new_chapter.name():
                self[i] = new_chapter
                return
        self.append(new_chapter)

    def get_chapter(self, name):
        for chapter in self:
            if chapter.name() == name:
                return chapter
        c = ConfigChapter(name)
        self.append(c)
        return c

    def set_key(self, chapter, key, value):
        c = self.get_chapter(chapter)
        k = c.get_key(key)
        k.set_value(value)

    def reset_key(self, chapter, key):
        c = self.get_chapter(chapter)
        c.reset_key(key)


class ConfigChapter(list):
    """
    Every ConfigChapter has a name, and is a list of ConfigLines.
    Like
    ```
    [ chapter1 ]
    key1 = value1
    .include /what/ever/file.config
    ```
    would be a ConfigChapter with name='chapter1' and having 2 ConfigLines (key1..., .include... and an empty list for 
    the last line).
    """
    __name = ""

    def __init__(self, name):
        super().__init__()
        self.__name = name

    def name(self):
        return self.__name

    def string(self):
        ret = []
        if self.__name:
            ret.append('[ {} ]'.format(self.__name))
        ret += [c.string() for c in self]
        return '\n'.join(ret)

    def get_key(self, name):
        for key in self:
            if key.name() == name:
                return key
        k = ConfigLine(name + '=')
        self.append(k)
        return k

    def reset_key(self, name):
        for i in range(len(self)):
            key = self[i]
            if key.name() == name:
                self.pop(i)
                return


class ConfigLine(list):
    """
    Every ConfigLine presents a config line in a config chapter in a config file.
    It just splits it up in `key = value` pairs, unless the first = character is after the first # character
    in which case it is comment.
    As such:
    - an empty line would end up being an empty list
    - a line without = before a # sign would become a list with 1 items
    - a line with = before # character would become a list with 2 elements

    ConfigLine cleans extra spaces for `key=value` lines (into `key = value`), and leaves comments where they are.
    A configLine with 2 elements are key=value lines and key then also is returned with the name() method.
    """

    def __init__(self, line):
        super().__init__()
        if '#' in line and line.find('=') > line.find('#'):
            self.append(line)
        else:
            for part in line.split('=', 2):
                part = part.strip()
                self.append(part)

    def name(self):
        if len(self) > 1:
            return self[0]
        else:
            return ""

    def set_value(self, value):
        key = self[0]
        self.clear()
        self.append(key)
        if value:
            self.append(value)

    def string(self):
        return " = ".join(self)