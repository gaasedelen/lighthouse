# Lighthouse - A Code Coverage Explorer for Reverse Engineers
<p align="center">
<img alt="Lighthouse Plugin" src="screenshots/overview.gif"/>
</p>

## Overview

Lighthouse is a code coverage plugin for [IDA Pro](https://www.hex-rays.com/products/ida/), and [Binary Ninja](https://binary.ninja/). The plugin makes use of interactive disassemblers to map, explore, and visualize externally collected code coverage data when symbols or source may not be available for a given binary.

This plugin is labeled only as a prototype & code resource for the community. 

Special thanks to [@0vercl0k](https://twitter.com/0vercl0k) for the inspiration.

## Releases

* v0.8 -- Binary Ninja support, HTML coverage reports, consistent styling, many tweaks, bugfixes.
* v0.7 -- Frida, C++ demangling, context menu, function prefixing, tweaks, bugfixes.
* v0.6 -- Intel pintool, cyclomatic complexity, batch load, bugfixes.
* v0.5 -- Search, IDA 7 support, many improvements, stability.
* v0.4 -- Most compute is now asynchronous, bugfixes.
* v0.3 -- Coverage composition, interactive composing shell.
* v0.2 -- Multifile support, performance improvements, bugfixes.
* v0.1 -- Initial release

# Installation

Lighthouse is a cross-platform (Windows, macOS, Linux) python plugin. It takes zero third party dependencies, making the code both portable and easy to install.

1. From your disassembler's python console, run the following command to find its plugin directory:
   - **IDA Pro**: `os.path.join(idaapi.get_user_idadir(), "plugins")`
   - **Binary Ninja**: `binaryninja.user_plugin_path()`

2. Copy the contents of this repository's `/plugin/` folder to the listed directory.

This project is primarily developed and tested with IDA for Windows, so that is where we expect the best experience. Support for Binary Ninja and other disassemblers is still considered exprimental at this time.

# Usage

Lighthouse loads automatically when a database is opened, installing a handful of menu entries into the disassembler.

<p align="center">
<img alt="Lighthouse Menu Entries" src="screenshots/open.gif"/>
</p>

These are the entry points for a user to load and view coverage data. To generate coverage data that can be loaded into Lighthouse, please look at the [README](https://github.com/gaasedelen/lighthouse/tree/develop/coverage) in the coverage directory of this repository.

## Coverage Painting

Lighthouse 'paints' the active coverage data across the three major IDA views as applicable. Specifically, the Disassembly, Graph, and Pseudocode views.

<p align="center">
<img alt="Lighthouse Coverage Painting" src="screenshots/painting.png"/>
</p>

In Binary Ninja, only the Disassembly and Graph views are supported.

## Coverage Overview

The Coverage Overview is a dockable widget that provides a function level view of the active coverage data for the database.

<p align="center">
<img alt="Lighthouse Coverage Overview" src="screenshots/overview.png"/>
</p>

This table can be sorted by column, and entries can be double clicked to jump to their corresponding disassembly.

## Context Menu

Right clicking the table in the Coverage Overview will produce a context menu with a few basic amenities.

<p align="center">
<img alt="Lighthouse Context Menu" src="screenshots/context_menu.gif"/>
</p>

These actions can be used to quickly manipulate or interact with entries in the table.

## Coverage Composition

Building relationships between multiple sets of coverage data often distills deeper meaning than their individual parts. The shell at the bottom of the [Coverage Overview](#coverage-overview) provides an interactive means of constructing these relationships.

<p align="center">
<img alt="Lighthouse Coverage Composition" src="screenshots/shell.gif"/>
</p>

Pressing `enter` on the shell will evaluate and save a user constructed composition.

## Composition Syntax

Coverage composition, or _Composing_ as demonstrated above is achieved through a simple expression grammar and 'shorthand' coverage symbols (A to Z) on the composing shell. 

### Grammar Tokens
* Logical Operators: `|, &, ^, -`
* Coverage Symbol: `A, B, C, ..., Z`
* Parenthesis: `(...)`

### Example Compositions
* `A & B`
* `(A & B) | C`
* `(C & (A - B)) | (F,H & Q)`

The evaluation of the composition may occur right to left, parenthesis are suggested for potentially ambiguous expressions.

## Hot Shell

Additionally, there is a 'Hot Shell' mode that asynchronously evaluates and caches user compositions in real-time.

<p align="center">
<img alt="Lighthouse Hot Shell" src="screenshots/hot_shell.gif"/>
</p>

The hot shell serves as a natural gateway into the unguided exploration of composed relationships.

## Search

Using the shell, one can search and filter the functions listed in the coverage table by prefixing their query with `/`.

<p align="center">
<img alt="Lighthouse Search" src="screenshots/search.gif"/>
</p>

The head of the shell will show an updated coverage % computed only from the remaining functions. This is useful when analyzing  coverage for specific function families.

## Jump

Entering an address or function name into the shell can be used to jump to corresponding function entries in the table.

<p align="center">
<img alt="Lighthouse Jump" src="screenshots/jump.gif"/>
</p>

## Coverage ComboBox

Loaded coverage data and user constructed compositions can be selected or deleted through the coverage combobox.

<p align="center">
<img alt="Lighthouse Coverage ComboBox" src="screenshots/combobox.gif"/>
</p>

## HTML Coverage Report

Lighthouse can generate a rudimentary HTML coverage report of the active coverage. 
A sample report can be seen [here](https://rawgit.com/gaasedelen/lighthouse/master/testcase/report.html).

<p align="center">
<img alt="Lighthouse HTML Report" src="screenshots/html_report.gif"/>
</p>

# Future Work

Time and motivation permitting, future work may include:

* ~~Asynchronous composition, painting, metadata collection~~
* ~~Multifile/coverage support~~
* Profiling based heatmaps/painting
* Coverage & profiling treemaps
* ~~Additional coverage sources, trace formats, etc~~
* Improved pseudocode painting
* ~~Lighthouse console access~~, headless usage
* ~~Custom themes~~
* ~~Python 3 support~~

I welcome external contributions, issues, and feature requests. Please make any pull requests to the `develop` branch of this repo.

# Authors

* Markus Gaasedelen ([@gaasedelen](https://twitter.com/gaasedelen))
