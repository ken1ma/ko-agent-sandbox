import { expect, test } from 'claude-code/testing'

const BAND = {
  plugin: 'managed-probe',
  component: 'AbovePrompt',
  props: {
    hasSurvey: false,
    isWorking: false,
    maxRows: 10,
    bodyColumns: 80,
    scroll: { offset: 0, bodyRows: 9 },
    view: {},
  },
} as const

test('the band names the plugin on each surface that has one, and yields to a survey', async $ => {
  for (const surface of ['terminal', 'desktop'] as const) {
    const band = await $.ui.mount({ ...BAND, surface })
    expect(await band.find({ type: 'Text', text: /managed-probe/ })).toBeDefined()
    await band.unmount()
    const survey = await $.ui.mount({ ...BAND, surface, props: { ...BAND.props, hasSurvey: true } })
    expect(await survey.find({ type: 'Text', text: /managed-probe/ })).toBeUndefined()
    await survey.unmount()
  }
})
