const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const files = [
  path.join(
    root,
    'node_modules',
    'react-native-web',
    'src',
    'modules',
    'useResponderEvents',
    'ResponderTouchHistoryStore.js'
  ),
  path.join(
    root,
    'node_modules',
    'react-native-web',
    'dist',
    'modules',
    'useResponderEvents',
    'ResponderTouchHistoryStore.js'
  ),
  path.join(
    root,
    'node_modules',
    'react-native-web',
    'dist',
    'cjs',
    'modules',
    'useResponderEvents',
    'ResponderTouchHistoryStore.js'
  )
];

const replacements = new Map([
  [
    files[0],
    {
      from: [
        '  } else {',
        '    console.warn(',
        "      'Cannot record touch end without a touch start.\\n',",
        '      `Touch End: ${printTouch(touch)}\\n`,',
        '      `Touch Bank: ${printTouchBank(touchHistory)}`',
        '    );',
        '  }',
        '}'
      ].join('\n'),
      to: ['  } else {', '    return;', '  }', '}'].join('\n')
    }
  ],
  [
    files[1],
    {
      from: [
        '  } else {',
        "    console.warn('Cannot record touch end without a touch start.\\n', \"Touch End: \" + printTouch(touch) + \"\\n\", \"Touch Bank: \" + printTouchBank(touchHistory));",
        '  }',
        '}'
      ].join('\n'),
      to: ['  } else {', '    return;', '  }', '}'].join('\n')
    }
  ],
  [
    files[2],
    {
      from: [
        '  } else {',
        "    console.warn('Cannot record touch end without a touch start.\\n', \"Touch End: \" + printTouch(touch) + \"\\n\", \"Touch Bank: \" + printTouchBank(touchHistory));",
        '  }',
        '}'
      ].join('\n'),
      to: ['  } else {', '    return;', '  }', '}'].join('\n')
    }
  ]
]);

for (const filePath of files) {
  if (!fs.existsSync(filePath)) {
    continue;
  }

  const original = fs.readFileSync(filePath, 'utf8');
  let updated = original;

  const replacement = replacements.get(filePath);
  if (replacement != null) {
    updated = updated.replace(replacement.from, replacement.to);
  }

  if (updated !== original) {
    fs.writeFileSync(filePath, updated);
    console.log(`patched ${path.relative(root, filePath)}`);
  }
}