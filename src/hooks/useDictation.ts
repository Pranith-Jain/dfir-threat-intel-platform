/**
 * useDictation — Web Speech API hook (Fleet-parity "Voice Dictation").
 *
 * Chrome/Edge/Safari ship SpeechRecognition; Firefox does not. The hook
 * degrades to `supported: false` so callers can hide the mic button.
 * Interim results stream into the transcript live; final segments append
 * on end-of-utterance.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { errMessage } from '../lib/log';

interface SpeechRecognitionLike {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  start(): void;
  stop(): void;
  abort(): void;
  onresult:
    | ((e: {
        resultIndex: number;
        results: ArrayLike<ArrayLike<{ transcript: string }> & { isFinal: boolean }>;
      }) => void)
    | null;
  onerror: ((e: { error?: string }) => void) | null;
  onend: (() => void) | null;
}

type SpeechRecognitionCtor = new () => SpeechRecognitionLike;

function getRecognitionCtor(): SpeechRecognitionCtor | null {
  const w = window as unknown as {
    SpeechRecognition?: SpeechRecognitionCtor;
    webkitSpeechRecognition?: SpeechRecognitionCtor;
  };
  return w.SpeechRecognition ?? w.webkitSpeechRecognition ?? null;
}

export function useDictation(onFinal: (text: string) => void) {
  const [listening, setListening] = useState(false);
  const [interim, setInterim] = useState('');
  const [error, setError] = useState('');
  const recRef = useRef<SpeechRecognitionLike | null>(null);
  const finalRef = useRef(onFinal);
  // Whether the user still wants hands-free mode (drives onend auto-restart).
  const wantsRef = useRef(false);
  finalRef.current = onFinal;
  const supported = typeof window !== 'undefined' && getRecognitionCtor() !== null;

  const stop = useCallback(() => {
    wantsRef.current = false;
    recRef.current?.stop();
    setListening(false);
    setInterim('');
  }, []);

  const start = useCallback(() => {
    const Ctor = getRecognitionCtor();
    if (!Ctor) return;
    setError('');
    try {
      const rec = new Ctor();
      rec.continuous = true;
      rec.interimResults = true;
      rec.lang = 'en-US';
      rec.onresult = (e) => {
        let interimText = '';
        for (let i = e.resultIndex; i < e.results.length; i++) {
          const res = e.results[i];
          if (!res) continue;
          const text = res[0]?.transcript ?? '';
          if (res.isFinal) {
            const trimmed = text.trim();
            if (trimmed) finalRef.current(trimmed);
          } else {
            interimText += text;
          }
        }
        setInterim(interimText);
      };
      const FATAL_ERRORS = new Set(['not-allowed', 'service-not-allowed', 'audio-capture']);
      rec.onerror = (e) => {
        if (e.error === 'not-allowed') setError('microphone permission denied');
        else if (e.error === 'no-speech') {
          // Routine during pauses in Chrome — NOT fatal: keep hands-free
          // mode alive and let onend auto-restart handle it.
          setError('');
          return;
        } else if (e.error && e.error !== 'aborted') setError(e.error);
        // Only fatal errors end the session.
        if (!e.error || FATAL_ERRORS.has(e.error) || e.error === 'no-speech') return;
        wantsRef.current = false;
        setListening(false);
      };
      rec.onend = () => {
        // Chrome auto-stops after silence; restart while the user still
        // wants dictation so long investigations stay hands-free. start()
        // lives OUTSIDE the state updater — StrictMode double-invokes
        // updaters, which would throw "already started" and desync state.
        if (wantsRef.current) {
          try {
            rec.start();
            setListening(true);
          } catch {
            setListening(false);
          }
        } else {
          setListening(false);
        }
      };
      recRef.current = rec;
      rec.start();
      wantsRef.current = true;
      setListening(true);
    } catch (e) {
      setError(errMessage(e));
    }
  }, []);

  useEffect(
    () => () => {
      recRef.current?.abort();
    },
    []
  );

  return { supported, listening, interim, error, start, stop, toggle: () => (listening ? stop() : start()) };
}
