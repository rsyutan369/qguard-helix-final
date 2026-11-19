import { Composition } from 'remotion';
import { CampaignFilm } from './CampaignFilm';

export function FilmRoot() {
  return <>
    <Composition id="QGuardHelixHD" component={CampaignFilm} width={1920} height={1080}
      durationInFrames={2880} fps={24} defaultProps={{ portrait: false, withAudio: true }} />
    <Composition id="QGuardHelixVertical" component={CampaignFilm} width={1080} height={1920}
      durationInFrames={1080} fps={24} defaultProps={{ portrait: true, withAudio: true }} />
  </>;
}
