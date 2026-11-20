//! GF(1024) as §3.2 defines it: the polynomials over GF(2) modulo
//! x^10 + x^3 + 1, `a` = x (the value 2), and the Reed–Solomon arithmetic the
//! words' check and its correction need.

/// x^10 + x^3 + 1.
const MODULUS: u16 = 0x409;

/// The field's nonzero elements, `a^0` to `a^1022`; `a` generates them all.
const ORDER: usize = 1023;

/// `EXP[i]` is `a^i`, and `LOG[v]` the `i` with `a^i = v` (`LOG[0]` unused).
static TABLES: ([u16; ORDER], [u16; 1024]) = tables();

const fn tables() -> ([u16; ORDER], [u16; 1024]) {
    let mut exp = [0u16; ORDER];
    let mut log = [0u16; 1024];
    let mut v: u16 = 1;
    let mut i = 0;
    while i < ORDER {
        exp[i] = v;
        log[v as usize] = i as u16;
        v <<= 1;
        if v & 0x400 != 0 {
            v ^= MODULUS;
        }
        i += 1;
    }
    (exp, log)
}

/// The generator's coefficients below its leading 1, highest power first:
/// g(x) = (x − a)(x − a^2)…(x − a^6) = x^6 + 0x07E x^5 + 0x083 x^4 + 0x34F
/// x^3 + 0x110 x^2 + 0x09E x + 0x082 (§3.2).
pub const GENERATOR: [u16; 6] = [0x07E, 0x083, 0x34F, 0x110, 0x09E, 0x082];

/// `a^i`.
pub fn exp(i: u32) -> u16 {
    TABLES.0[i as usize % ORDER]
}

/// The product of two elements.
pub fn mul(x: u16, y: u16) -> u16 {
    if x == 0 || y == 0 {
        return 0;
    }
    let (exp, log) = &TABLES;
    exp[(usize::from(log[usize::from(x)]) + usize::from(log[usize::from(y)])) % ORDER]
}

/// The inverse of a nonzero element.
fn inv(x: u16) -> u16 {
    let (exp, log) = &TABLES;
    exp[(ORDER - usize::from(log[usize::from(x)])) % ORDER]
}

/// The polynomial whose coefficients, highest power first, are `poly`, at `x`.
pub fn eval(poly: &[u16], x: u16) -> u16 {
    poly.iter().fold(0, |acc, &c| mul(acc, x) ^ c)
}

/// §3.2's `polymod`: the remainder, modulo the generator whose coefficients
/// below its leading 1 are `g`, of the polynomial whose coefficients are 1
/// and then `symbols`; its coefficients highest first. The register starts
/// at 1, which stands for the leading 1.
pub fn polymod<const K: usize>(g: &[u16; K], symbols: impl IntoIterator<Item = u16>) -> [u16; K] {
    let mut rem = [0u16; K];
    rem[K - 1] = 1;
    for s in symbols {
        let top = rem[0];
        rem.copy_within(1.., 0);
        rem[K - 1] = s;
        for (r, &c) in rem.iter_mut().zip(g) {
            *r ^= mul(top, c);
        }
    }
    rem
}

/// The values `y` at the places (powers of x) `p` for which, for j = 1 to
/// the number of syndromes, the sum of `y[k] * a^(j * p[k])` is the j-th
/// syndrome; None if no values satisfy every equation.
pub fn solve(places: &[u32], syndromes: &[u16]) -> Option<Vec<u16>> {
    let u = places.len();
    let mut rows: Vec<Vec<u16>> = (0..syndromes.len())
        .map(|j| {
            let mut row: Vec<u16> = places.iter().map(|&p| exp((j as u32 + 1) * p)).collect();
            row.push(syndromes[j]);
            row
        })
        .collect();
    let mut rank = 0;
    for col in 0..u {
        let pivot = (rank..rows.len()).find(|&r| rows[r][col] != 0)?;
        rows.swap(rank, pivot);
        let scale = inv(rows[rank][col]);
        for v in &mut rows[rank] {
            *v = mul(*v, scale);
        }
        let lead = rows[rank].clone();
        for (r, row) in rows.iter_mut().enumerate() {
            if r != rank && row[col] != 0 {
                let factor = row[col];
                for (v, &l) in row.iter_mut().zip(&lead) {
                    *v ^= mul(factor, l);
                }
            }
        }
        rank += 1;
    }
    if rows[rank..].iter().any(|row| row[u] != 0) {
        return None;
    }
    Some(rows[..u].iter().map(|row| row[u]).collect())
}

/// Calls `f` with every choice of `k` of the indices `0..n`, in increasing
/// order, until it returns true.
pub fn each_combination(n: usize, k: usize, f: &mut dyn FnMut(&[usize]) -> bool) {
    if k > n {
        return;
    }
    let mut pick: Vec<usize> = (0..k).collect();
    loop {
        if f(&pick) {
            return;
        }
        let Some(i) = (0..k).rev().find(|&i| pick[i] < n - k + i) else {
            return;
        };
        pick[i] += 1;
        for j in i + 1..k {
            pick[j] = pick[j - 1] + 1;
        }
    }
}
