`rf2_puppeteer` is an rFactor 2 plugin that changes original behavior and lets bots have different ai level and agression. It spreads your chosen strength/aggression range across the grid, and it can give bots a little revenge boost when they get overtaken.

## What it does
- **Sets AI strength and aggression at session start.** Bots are assigned values across the grid: first car gets `StrengthFirst/AggrFirst`, last car gets `StrengthLast/AggrLast`, and everyone in between gets interpolated values.
- **Triggers revenge when a bot is overtaken.** If a local AI loses position to another car, it can get a temporary boost to `RevengeStrength` / `RevengeAggr` for `RevengeCooldown` seconds, then go back to normal.
- It makes [TAB] car labels look like '1.Name Strength,Aggression'

## Key settings in CustomPluginVariables.JSON
Setting Default Meaning
`StrengthFirst` / `StrengthLast` 95 / 120 AI strength range across the grid
`AggrFirst` / `AggrLast` 20 / 40 AI aggression range across the grid
`Revenge` 120 Master revenge switch/value (`0` disables)
RevengeStrength/RevengeAggr 120 / 120 Temporary revenge boost
`RevengeCooldown` 60 Revenge duration, seconds
`RevengeBots` 5 Max revenging bots at once

install `rf2_puppeteer.dll` to `rFactor 2\Bin64\Plugins\`
