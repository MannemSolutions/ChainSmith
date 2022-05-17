"""
This module sort of does the same as configparser, but with a few distinctions:
1: openssl.cnf has items outside of a section (before first section header),
but configparser can not work with such config.
2: openssl.cnf can have values that are not formatted `key = value`.
one example would be:
   .include /etc/crypto-policies/back-ends/opensslcnf.config

For these 2 reasons, we have added this module to process openssl.cnf instead.

The config module reads a config file and parses it into a processable objects:
- a ConfigFile which represents the file and is a list of ConfigChapters
- a ConfigChapter, which represent one chapter and is a list of ConfigLines
- a ConfigLine, which represents a line and is actually either
  - an empty line would end up being an empty list
  - a line without = before a # sign would become a list with 1 items
  - a line with = before # character would become a list with 2 elements
"""
from os import path


class ConfigFile(list):
    """
    ConfigFile is the main placeholder for all config in a file.
    It is a list of config sections, where every config section
    is of type ConfigChapter.
    """
    def __init__(self, file):
        super().__init__()
        file = path.realpath(path.expanduser(file))
        chapter = ConfigChapter('')
        self.append(chapter)
        with open(file, encoding="utf8") as config_file:
            for line in config_file:
                line = line.strip()
                if len(line) == 0:
                    chapter.append(ConfigLine(line))
                elif line[0] == '[' and line[-1] == ']':
                    chapter = ConfigChapter(line[1:-1].strip())
                    self.append(chapter)
                else:
                    chapter.append(ConfigLine(line))

    def write(self, file):
        """
        Write the config to a file
        :param file: the path of the file to write to
        :return:
        """
        file = path.realpath(path.expanduser(file))
        try:
            with open(file, 'w', encoding="utf8") as config_file:
                config_file.write(self.string())
        except OSError as os_err:
            print('Cannot open file:', os_err)

    def string(self):
        """
        Return a string representation of this config file.
        :return: a string representation of this config file.
        """
        return '\n'.join([cc.string() for cc in self])

    def set_chapter(self, new_chapter):
        """
        Add or replace a chapter in the config file
        :param new_chapter: The chapter to add. Should eb of type ConfigChapter
        :return:
        """
        for i, chapter in enumerate(self):
            if chapter.name() == new_chapter.name():
                self[i] = new_chapter
                return
        self.append(new_chapter)

    def get_chapter(self, name):
        """
        find and return a chapter by ots name
        :param name: the name of the chapter to find
        :return: the chapter
        """
        for chapter in self:
            if chapter.name() == name:
                return chapter
        chapter = ConfigChapter(name)
        self.append(chapter)
        return chapter

    def set_key(self, chapter_name, key, value):
        """
        Add or set a value to a key in a chapter
        :param chapter_name: The chapter to hold the parameter
        :param key: The name of the parameter
        :param value: The value of the parameter
        :return:
        """
        chapter = self.get_chapter(chapter_name)
        line = chapter.get_key(key)
        line.set_value(value)

    def reset_key(self, chapter_name, key):
        """
        remove a parameter from a chapter
        :param chapter_name: The chapter to remove the parameter from
        :param key: the key of the line to remove
        :return:
        """
        chapter = self.get_chapter(chapter_name)
        chapter.reset_key(key)


class ConfigChapter(list):
    """
    Every ConfigChapter has a name, and is a list of ConfigLines.
    Like
    ```
    [ chapter1 ]
    key1 = value1
    .include /what/ever/file.config
    ```
    would be a ConfigChapter with name='chapter1' and having 2 ConfigLines
    (key1..., .include... and an empty list for the last line).
    """
    __name = ""

    def __init__(self, name):
        super().__init__()
        self.__name = name

    def name(self):
        """Return the name of the chapter"""
        return self.__name

    def string(self):
        """Return a string representation of the chapter"""
        ret = []
        if self.__name:
            ret.append(f'[ {self.__name} ]')
        ret += [c.string() for c in self]
        return '\n'.join(ret)

    def get_key(self, key_name):
        """Get a parameter by ots key"""
        for key in self:
            if key.name() == key_name:
                return key
        line = ConfigLine(key_name + '=')
        self.append(line)
        return line

    def reset_key(self, key):
        """Clear a parameter"""
        for i, line in enumerate(self):
            if line.name() == key:
                self.pop(i)
                return


class ConfigLine(list):
    """
    Every ConfigLine presents a config line in a chapter in a config file.
    It just splits it up in `key = value` pairs,
    unless the first = character is behind the first # character
    in which case it is comment.
    As such:
    - an empty line would end up being an empty list
    - a line without = before a # sign would become a list with 1 items
    - a line with = before # character would become a list with 2 elements

    ConfigLine cleans extra spaces for `key=value` lines (into `key = value`),
    and leaves comments where they are.
    A configLine with 2 elements are key=value lines
    and key then also is returned with the name() method.
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
        """Return the name (key) of his line"""
        if len(self) > 1:
            return self[0]
        return ""

    def set_value(self, value):
        """Set the value of a line in a key = value pair"""
        key = self[0]
        self.clear()
        self.append(key)
        if value:
            self.append(value)

    def string(self):
        """Return a string representation of a line"""
        return " = ".join(self)
