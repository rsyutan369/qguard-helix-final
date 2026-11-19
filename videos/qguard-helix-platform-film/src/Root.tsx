import { Composition } from 'remotion';
import { EnterpriseFilm } from './EnterpriseFilm';

export function FilmRoot() {
  return <Composition id="QGuardHelixPlatform" component={EnterpriseFilm}
    width={1920} height={1080} durationInFrames={4320} fps={24}
    defaultProps={{ includeAudio: true }} />;
}
