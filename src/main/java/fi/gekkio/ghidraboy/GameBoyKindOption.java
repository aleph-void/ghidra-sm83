// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fi.gekkio.ghidraboy;

import ghidra.app.util.Option;

// The hardware type choice. Ghidra shows an enum-valued option as a drop-down. (An earlier version
// added radio buttons through Option.getCustomEditorComponent(), whose signature changed in Ghidra
// 12.2 (it takes an AddressFactoryService), so one source could not build for 12.1 and 12.2.)
public class GameBoyKindOption extends Option {
    public GameBoyKindOption(String name, GameBoyKind value) {
        super(name, GameBoyKind.class, value, null, null);
    }

    public GameBoyKindOption(String name, GameBoyKind value, String arg, String group) {
        super(name, GameBoyKind.class, value, arg, group);
    }

    @Override
    public Option copy() {
        return new GameBoyKindOption(this.getName(), (GameBoyKind) this.getValue(), this.getArg(), this.getGroup());
    }
}
