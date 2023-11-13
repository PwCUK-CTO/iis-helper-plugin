# IISHelper Plugin
IDA Pro plugin to aid with the analysis of native IIS modules.

## Installation
Copy both `iis_helper_plugin.py` and `iis_helper_classes.py` to the `plugins` directory of your IDA Pro installation.

For example, if using IDA 8.3 on Windows, you can find this directory as `%PROGRAMFILES%\IDA Pro 8.3\plugins`.

## Running the plugin
To run the plugin, either go to `Edit -> Plugins -> IISHelper`, or use the shortcut `CTRL+ALT+I`. This plugin will then take the following actions:
- Loading in relevant classes/symbolic constants;
- Identifying and renaming the virtual methods of IIS classes;
- Applying function prototypes to the known implemented virtual methods; and,
- Attempting initial retyping of variables in these methods.

Once the script has finished running, you can locate the implemented methods to determine the ones of interest, and start reverse engineering them further.

## Example output
**Retyping the RegisterModule export:**
![Retyped RegisterModule export](/images/registermodule_comparison.png)

**Automatically renamed virtual methods for the IIS class:**
![Renamed virtual methods](/images/virtual_methods_comparison.png)

**Automatically retyped variables for a implemented method:**
![Retyped example function](/images/retyped_function_comparison.png)
