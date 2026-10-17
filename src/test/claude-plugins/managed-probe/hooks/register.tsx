// Under the image's allowManagedHooksOnly this hook runs only when the plugin is managed, so the
// band is the measurement: drawn, --claude-plugin-dir made the plugin managed; absent, it did not.
import type { Register } from 'claude-code'

export const register: Register = on => {
  on('ui.render', { component: 'AbovePrompt' }, ($, e, next) => {
    if (e.props.hasSurvey) {
      return next(e)
    }
    const { Box, Text } = $.ui.resolve(e)
    return (
      <Box>
        <Text>managed-probe draws this band: its hooks run</Text>
      </Box>
    )
  })
}
