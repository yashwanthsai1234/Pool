/** The fields of a TD3 (passport) MRZ. Text is A-Z, 0-9 and space; dates are YYMMDD. */
export interface MrzInput {
  documentNumber: string;
  surname: string;
  givenNames: string;
  dateOfBirth: string;
  sex: 'M' | 'F' | '<';
  dateOfExpiry: string;
  personalNumber?: string;
  /** Issuing State and nationality. Default `XXA`, the ICAO sample code that MRZ parsers accept. */
  country?: string;
}

const value = (c: string): number => {
  if (c === '<') return 0;
  if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
  if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 55;
  throw new RangeError(`not an MRZ character: ${JSON.stringify(c)}`);
};

/**
 * MRZ check digit: values 0-9, A-Z = 10-35, `<` = 0; weights 7, 3, 1 repeating; sum mod 10.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p3_cons_en.pdf (section 4.9)
 */
export function checkDigit(field: string): string {
  let sum = 0;
  for (let i = 0; i < field.length; i++) sum += value(field[i] ?? '<') * ([7, 3, 1][i % 3] ?? 1);
  return String(sum % 10);
}

function field(text: string, width: number, what: string, pattern = /^[A-Z0-9<]*$/): string {
  const f = text.trim().replace(/ +/g, '<');
  if (!pattern.test(f) || f.length > width)
    throw new RangeError(`${what} does not fit the MRZ: ${JSON.stringify(text)}`);
  return f.padEnd(width, '<');
}

const date = (d: string, what: string) => field(d, 6, what, /^\d{6}$/);

/**
 * Builds the 88-character TD3 MRZ (2 lines of 44, concatenated). Throws RangeError on input that does not fit,
 * because silently truncating a fixture would hide a test mistake.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p4_cons_en.pdf (section 4.2.2)
 */
export function td3(m: MrzInput): string {
  const country = field(m.country ?? 'XXA', 3, 'country', /^[A-Z<]{3}$/);
  const names = field(`${m.surname.trim()}<<${m.givenNames.trim()}`, 39, 'name', /^[A-Z<]+$/);
  const doc = field(m.documentNumber, 9, 'document number');
  const dob = date(m.dateOfBirth, 'date of birth');
  const exp = date(m.dateOfExpiry, 'date of expiry');
  const opt = field(m.personalNumber ?? '', 14, 'personal number');
  const optCd = opt === '<'.repeat(14) ? '<' : checkDigit(opt);
  const docPart = doc + checkDigit(doc);
  const dobPart = dob + checkDigit(dob);
  const expPart = exp + checkDigit(exp) + opt + optCd;
  const composite = checkDigit(docPart + dobPart + expPart);
  return `P<${country}${names}${docPart}${country}${dobPart}${m.sex}${expPart}${composite}`;
}
