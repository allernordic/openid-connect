declare const expect: (typeof import('chai'))['expect'];

declare namespace Express {
  interface Request {
    appSession?: Record<string, any>;
    mySession?: Record<string, any>;
  }
}
