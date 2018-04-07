# chacho-sorter: Sort files based on their characteristics

This is a file sorter/organizer written in Python for learning purposes. The implementation is
still naive, but the basic principles are already laid down.

# chacho-sorter rule format

## Fields

### name

* Used only for identification purposes. It does not have any effect on the
rule behaviour
* For example, "TXT file", or "Picture in PNG format"

### target

* String which indicates which kind of file will be affected by this rule.
* How this target is interpreted depends on the *type* option. If such option
  is not present, it defaults to *extension*.

### type

* It specifies the type of target being used to determine to which files will
  this rule be applied to
* Possible values are:
    * *regex*: regular expression
    * *extension*: filename extension, e.g. "txt", "png", etc.
    * *format*: file format, as provided by the 'file' utility

### destination

* It indicates to which directory will the target be moved

### action

* *remove*: remove file from system
* *move*: move to another directory. This requires "destination" field to be
  set
* *ignore*: ignore this file.

### condition

* The format depends on the properties being used
* Different types of properties can not be mixed
* If more than one condition is specified, ALL of them must be met for the rule
  to be applied

#### Time conditions:

* PROPERTY1 is QUANTITY (SMALLER|SMALLEREQ|EQUAL|BIGGEREQ|BIGGER) than
  PROPERTY2
* PROPERTY1|2 can be of the following types:
    * MODIFICATION: date of last modification of the file
    * ACCESS: date of last access to the file
    * METACHANGE: date of last metadata modification of the file
    * CURRENTDATE: current date of the system. N.B: this is a
    property of the system and not of the file
* QUANTITY must be expressed as a string with the following format
    * NumberUnit NumberUnit NumberUnit..., or NumberUnitNumberUnitNumberUnit...
    * For example: "3m 2d 4H 1M", or "3m2d4H1M". This translates to "3 months, 2 days, 4
      hours and 1 minute"
    * Number can be anything from 0 to 65535.
    * Allowed units are: years (Y), months (m), days (d), hours (H),
      minutes (M) and seconds (S)
    * It might be expressed as a single word or as several words separated
      by spaces
    * Units cannot be repeated more than once, e.g. "2d 2d" is not a valid
      QUANTITY

#### Size conditions:

* SIZE is (SMALLER|SMALLEREQ|EQUAL|BIGGEREQ|BIGGER) than QUANTITY
* SIZE: indicates that the condition is based on the file size in disk of the
  file
* QUANTITY must be expressed as a string with the following format
    * NumberUnit
    * For example: "3GiB"
    * Number can be anything from 0 to 65535
    * Allowed units are: terabytes (TiB), gibabytes (GiB), megabytes (MiB),
      kilobytes (KiB) and bytes (B).
