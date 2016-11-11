# Adding new modules to BroPSA

## 1 Introduction

Each BroPSA module consist of two parts:

*  **A Python class**: this part is used as PSA's interface to the module and
  to the Bro script. It's main tasks are 1) parsing configuration rules to a
  format suitable for the corresponding Bro script, 2) formatting Bro script's
  outputs for the BroPSA logs etc., and 3) communication with the Bro script.
  However, Python part of the module may, as an example, also make more complex
  computations related to the actual monitoring task as Python allows more
  flexibility compared to Bro NSM scripting language.
*  **A Bro script**: this part implements the actual monitoring code.

### 1.1 Creating a new Python module

Modules are placed in the *modules* directory of the PSA source code tree. Each
module's Python part must contain a class that inherits from the
[BroModule](../PSA/modules/BroModule.py) class. Each class must define a global
variable called *module* that must be initialized with the class constructor.
The constructor must take a single argument, a logger object, that must be
passed to parent class' constructor. It can be later accessed using a member
variable of the same name. The first argument given to the parent's constructor
is the name of the Bro scripts file corresponding to this module.

```
from modules.BroModule import BroModule

...

class MYModule( BroModule ):

    def __init__( self, logger ):
        super( MyModule, self ).__init__( 'my-module.bro', logger )
        ...
...

module = MyModule
```

A BroModule implements four function that can be overridden in the child
classes.

Function *onStart* is called after Bro NSM is started and the Bro script
part of the module becomes available. The main purpose of this function is
to pass configuration options to the Bro script. Take function takes a single
parameter that is a connection object connected to Bro. It **must** be passed
to parent class' onStart function. It can be later accessed using a member
variable of the same name.

```
    def onStart( self, connection ):
        super( MyModule, self ).onStart( connection )
        ...
```

Function *onStop* is called before Bro NSM is stopped and the Bro script
part of the module becomes unavailable. The main purpose of this function is
to perform any tasks related to shutting down the module. The function must call
parent class' onStop function.

```
    def onStop( self ):
        super( MyModule, self ).onStop()
        ...
```

Function *onRule* is called by BroPSA once for each configuration rule in the
PSA configuration related to the module. This function takes a single argument,
the rule object, and must return True if it was able to process the rule, or
False otherwise.

```
    def onRule( self, rule ):
        ...
```

Function *onEvent* is used to pass events from the Bro script to the Python part
of the module. It takes a single argument that is the event sent by the Bro
script. This function is explained in more detail in Section 2.2.

```
    def onEvent( self, data ):
        ...

```

**NOTE**: Easiest way to to create a new Python module is to copy and modify
some of the existing modules.

### 1.2 Creating a Bro NSM script

Refer to [Bro NSM documentation](https://www.bro.org/sphinx/scripting/)

**NOTE**: All Bro modules used with BroPSA should work in Bro NSM bare mode!

# 2 Communication between Bro and Python

The Python part and the Bro script part of a module communicate using Broccoli
Python bindings.

## 2.1 From Python to Bro

### 2.1.1 In Python code

Import required functions from Broccoli:

```
from broccoli import event, record_type, record, addr, port, count
```

Define a record type for the message. Record contents should be a list of field
names that correspond to those defined in the Bro script (see Section 2.2.1).

```
MyInRecord = record_type( ... )
```

**Example:**
```
MyInRecord = record_type( 'op' )
```

To send a new record, a record must first be created using the *record*
function. After this the record is filled with the actual data. Each of the
defined fields should contain *some* value. All the fields of the record must be
initialized using suitable function (e.g., str(), addr(), port(), count()) that
matches the corresponding field's type in the Bro script to ensure they are
encoded correctly.

Records are sent using the Broccoli Connection stored in the Module object's
member variable *connection*. The first argument given to the function is the
event name, which can be freely chosen. The connection object should only be
used between the calls to modules *onStart* and *onStop* methods. Otherwise
message will not be passed to the Bro script.

**Example:**
```
    try:
        rec         = record( MyInRecord )
        rec.op      = str( 'MyString' )
        self.connection.send( 'on_my_event', rec )
    except Exception:
        ...
```

**Note**: Broccoli and it's Python Bindings provide a very simple interface to
Bro script and not all the Bro script features are supported. Thus, the message
format should be relatively simple. Complex types, such as containers, should
not be used in the message content.

### 2.1.2 In Bro code

Module's *init* callback should subscribe for all Bro events the module wants to
receive. This is performed using utilities in [psa-utils.bro](PSA/modules/psa-utils.bro).
Thus, this script file must first be loaded into the module script:

```
@load ./psa-utils
```

Subscription is made using the function:

```
function subscribe_events( events : pattern )
```

The pattern argument should have a Bro pattern that captures the event name
used in *send* function in the Python code.

The Bro script must define a record type matching the record type defined in the
Python code. In addition, an event handler must be defined to capture the
corresponding event. This event handler's name must match the given event name
and take one parameter of the defined record type.

**Example:**
```
type MyInRecord: record
{
    op: string;
};

event on_my_event( rec: MyInRecord )
{
    ...
}

event bro_init() &priority=9
{
    PSA::subscribe_events( /on_my_event/ );
}
```

## 2.2 From Bro to Python

### 2.2.1 In Bro code

An ouput record must be defined similarly to defining the input record in
Section 2.1.2. In addition, an event handler must be declared for that record.

```
type MyOutRecord : record
{
    op: string;
};

global my_event: event( data: MyOutRecord );
```

A new event is sent simply by creating and filling the event record and then
calling the event handler:

```
   local data: MyOutRecord;
   # fill the record
   data$op = "MyData";
   event report_count( data );

```

### 2.2.2 In Python code

In the Python code an event handler must be defined for the Bro event.
Event handlers are always global functions not related to any specific
object instaces. BroEventDispatcher is used to pass the event to the
actual BroModule object.

In order to receive events, the module must import BroEventDispatcher
and register itself with the dispatcher using the function *register*.
The function takes a key (any string) and an object as arguments. The
given object must implement function called *onEvent* as it is defined
in the BroModule. See Section 1.1 for more details.

**Example**:
```
import modules.BroEventDispatcher as BroEventDispatcher

...

MyModuleKey = 'MyModuleEvent'

...

class MYModule( BroModule ):

...

    def __init__( self, logger ):
        ...
        BroEventDispatcher.register( MyModuleKey, self )
        ...
```

A record type must be defined similarly to the input record in Section
2.1.1.

**Example**;
```
MyOutRecord = record_type( 'op' )
```

Event handlers a defined using @event decorators. The decorator statement should
take the defined record as its argument. The actual event handler function takes
a single argument that is the Bro record. In order to pass this record to the
module object, the event handler must call BroEventDispatcher's *dispatch*
function with the key registered for the module object and the received record.

```
@event( MyOutRecord )
def report_count( data ):
    BroEventDispatcher.dispatch( MyModuleKey, data )
```

The record will be eventually passed to module's *onEvent* function for further
processing.

```
    def onEvent( self, data ):
        ...
```

## 3. Loading a module at runtime

BroPSA loads modules dynamically based on the PSA configuration file and
module description file [*modules.json*](../PSA/modules.json). The latter is
used to map *operations* in rule definitions of the former file to correct
module implementations. Each module available at runtime should have an entry
in the modules file:

```
{
    "modules": [
...
        {
            "name": "MyOperation",
            "module": "modules/MyModule.py"
        }
...
    ]
}
```

where:

*  The value of the *name* attribute must match the value of the *operation*
   attribute of any rules related to this module in the BroPSA configuration
   file.
*  The value of the *module* attribute must contain a (relative) path to the
   Python file containing the global *module* variable initialized to module's
   BroModule class' constructor function.

In order to be loaded a module must match to at least one rule in the PSA
configuration file. The rule is needed **even** if the module does not actually
use any configuration options. Thus, the *PSA/psaConfigs/psaconf* file should
contain a *rule* entry of the following format:

```
{

   "rules": [
...
     { "id": "MyRule",
       "hspl": {
         "id": "MyRule",
         "text": "MyHSPL"
       },
       "event": "EVENT_CONNECTION",
       "operation": "MyOperation",
       "parameters": [
           { "type": "MyParameter",
             "value": "MyValue"
           }
       ],
       "action": "log",
       "conditions": [
          { "type": "MyCondition",
            "value": "MyValue"
          }
...
       ]
     }
}
```

All of the following attributes must exist:

*  The *id* attribute must be a unique rule ID (in file scope)
*  The *hspl* attribute should specify the HSPL rule related to this rule. The
   *id* and the *text* attribute should come directly from the MSPL definition.
   In case the configuration is written by hand, these attributes may contain
   any string values, but they should still be present.
*  The *operation* attribute must contain a module specific identifier that can
   be chosen freely. This identifier must match to some module entry in the
   *modules.json* file
*  The *conditions* and *parameters* attributes may be empty lists or they may
   contain module specific key-value pairs. Each of these pairs must have two
   attributes: *type* and *value*. The value of the *type* attribute must be a
   string and should describe the parameter. Value of the *value* attribute
   can be any JSON object. Although, if the attribute has a complex values,
   e.g., an object, changes might be needed into the configuration parsing
   code.
*  The *action* attribute must contain value *log*, as it is currently the only
   supported action.
*  The *event* attribute must contain one of the values *EVENT_CONNECTION* or
   *EVENT_FILE*. However, this attribute is currently not used.



## 4. Adding new configuration options

You are on your own, bro...
