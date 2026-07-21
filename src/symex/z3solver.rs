//! z3 backend for the solver trait.

use super::solver::{Constraint, Solver, Term};
use crate::ir::pb;
use z3::ast::{Ast, BV};

pub(crate) struct Z3Solver {
    ctx: z3::Context,
}

impl Z3Solver {
    pub(crate) fn new() -> Self {
        Self {
            ctx: z3::Context::new(&z3::Config::new()),
        }
    }

    /// Packet variable: one bitvector of `packet_bits` (>=1 dummy bit
    /// when the packet is empty, kept unconstrained and unread).
    fn packet<'a>(&'a self, packet_bits: usize) -> BV<'a> {
        BV::new_const(&self.ctx, "packet", packet_bits.max(1) as u32)
    }

    fn term<'a>(&'a self, packet: &BV<'a>, t: &Term) -> BV<'a> {
        match t {
            Term::Const(v) => BV::from_u64(&self.ctx, *v, 64),
            Term::Extract { bit_off, len } => {
                let total = packet.get_size() as usize;
                // MSB-first: bit_off 0 is the packet BV's highest bit.
                let hi = (total - 1 - bit_off) as u32;
                let lo = (total - bit_off - len) as u32;
                packet.extract(hi, lo).zero_ext(64 - *len as u32)
            }
            Term::Bin(op, l, r) => {
                let l = self.term(packet, l);
                let r = self.term(packet, r);
                match op {
                    pb::BinOpKind::Add => l.bvadd(&r),
                    pb::BinOpKind::Sub => l.bvsub(&r),
                    pb::BinOpKind::Mul => l.bvmul(&r),
                    pb::BinOpKind::Shl => l.bvshl(&r),
                    pb::BinOpKind::Shr => l.bvlshr(&r),
                    pb::BinOpKind::And => l.bvand(&r),
                    pb::BinOpKind::Or => l.bvor(&r),
                    pb::BinOpKind::Unspecified => unreachable!("validated IR"),
                }
            }
        }
    }

    fn constraint<'a>(&'a self, packet: &BV<'a>, c: &Constraint) -> z3::ast::Bool<'a> {
        match c {
            Constraint::Eq(t, v) => self.term(packet, t)._eq(&BV::from_u64(&self.ctx, *v, 64)),
            Constraint::Masked(t, value, mask) => {
                let m = BV::from_u64(&self.ctx, *mask, 64);
                self.term(packet, t)
                    .bvand(&m)
                    ._eq(&BV::from_u64(&self.ctx, value & mask, 64))
            }
            Constraint::InRange(t, lo, hi) => {
                let t = self.term(packet, t);
                z3::ast::Bool::and(
                    &self.ctx,
                    &[
                        &t.bvuge(&BV::from_u64(&self.ctx, *lo, 64)),
                        &t.bvule(&BV::from_u64(&self.ctx, *hi, 64)),
                    ],
                )
            }
            Constraint::Not(inner) => self.constraint(packet, inner).not(),
            Constraint::And(cs) => {
                let bools: Vec<_> = cs.iter().map(|c| self.constraint(packet, c)).collect();
                let refs: Vec<_> = bools.iter().collect();
                z3::ast::Bool::and(&self.ctx, &refs)
            }
        }
    }

    /// Read the completed model byte by byte (MSB-first; a partial
    /// trailing byte lands in the high bits, pad bits zero — canonical
    /// form by construction).
    fn model_packet(&self, model: &z3::Model, packet: &BV, packet_bits: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; packet_bits.div_ceil(8)];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let msb_off = 8 * i;
            let width = 8.min(packet_bits - msb_off);
            let hi = (packet_bits - 1 - msb_off) as u32;
            let lo = (packet_bits - msb_off - width) as u32;
            let v = model
                .eval(&packet.extract(hi, lo), true)
                .and_then(|b| b.as_u64())
                .unwrap_or(0);
            *byte = (v as u8) << (8 - width);
        }
        bytes
    }
}

impl Solver for Z3Solver {
    fn check(&mut self, packet_bits: usize, cs: &[Constraint]) -> Option<Vec<u8>> {
        let packet = self.packet(packet_bits);
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            solver.assert(&self.constraint(&packet, c));
        }
        match solver.check() {
            z3::SatResult::Sat => {
                let model = solver.get_model().expect("model after sat");
                Some(self.model_packet(&model, &packet, packet_bits))
            }
            _ => None,
        }
    }

    fn all_values(
        &mut self,
        packet_bits: usize,
        cs: &[Constraint],
        of: &Term,
        cap: usize,
    ) -> anyhow::Result<Vec<u64>> {
        let packet = self.packet(packet_bits);
        let solver = z3::Solver::new(&self.ctx);
        for c in cs {
            solver.assert(&self.constraint(&packet, c));
        }
        let term = self.term(&packet, of);
        let mut values = Vec::new();
        while solver.check() == z3::SatResult::Sat {
            let model = solver.get_model().expect("model after sat");
            let v = model
                .eval(&term, true)
                .and_then(|b| b.as_u64())
                .ok_or_else(|| anyhow::anyhow!("value eval failed"))?;
            values.push(v);
            if values.len() > cap {
                anyhow::bail!(
                    "length expression has more than {cap} feasible values; refusing to enumerate"
                );
            }
            solver.assert(&term._eq(&BV::from_u64(&self.ctx, v, 64)).not());
        }
        values.sort_unstable();
        Ok(values)
    }

    fn min_max(
        &mut self,
        packet_bits: usize,
        cs: &[Constraint],
        of: &Term,
    ) -> anyhow::Result<Option<(u64, u64)>> {
        // Solve the objective in the given direction under `cs`.
        // Lengths are small positive values (< 2^63), so unsigned vs.
        // signed BV optimization coincide.
        fn solve(
            s: &Z3Solver,
            packet_bits: usize,
            cs: &[Constraint],
            of: &Term,
            maximize: bool,
        ) -> anyhow::Result<Option<u64>> {
            let packet = s.packet(packet_bits);
            let opt = z3::Optimize::new(&s.ctx);
            for c in cs {
                opt.assert(&s.constraint(&packet, c));
            }
            let term = s.term(&packet, of);
            if maximize {
                opt.maximize(&term);
            } else {
                opt.minimize(&term);
            }
            match opt.check(&[]) {
                z3::SatResult::Sat => {
                    let model = opt.get_model().expect("model after sat");
                    let v = model
                        .eval(&term, true)
                        .and_then(|b| b.as_u64())
                        .ok_or_else(|| anyhow::anyhow!("value eval failed"))?;
                    Ok(Some(v))
                }
                _ => Ok(None),
            }
        }

        let Some(min) = solve(self, packet_bits, cs, of, false)? else {
            return Ok(None); // UNSAT
        };
        let max = solve(self, packet_bits, cs, of, true)?
            .ok_or_else(|| anyhow::anyhow!("maximize UNSAT after minimize SAT"))?;
        Ok(Some((min, max)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::pb::BinOpKind;

    fn ext(bit_off: usize, len: usize) -> Term {
        Term::Extract { bit_off, len }
    }

    #[test]
    fn trivial_sat_and_unsat() {
        let mut s = Z3Solver::new();
        let sat = s.check(16, &[Constraint::Eq(ext(0, 8), 0xAB)]);
        assert_eq!(sat.unwrap()[0], 0xAB);
        let unsat = s.check(
            16,
            &[
                Constraint::Eq(ext(0, 8), 1),
                Constraint::Not(Box::new(Constraint::Eq(ext(0, 8), 1))),
            ],
        );
        assert!(unsat.is_none());
    }

    #[test]
    fn extract_is_msb_first() {
        let mut s = Z3Solver::new();
        // Constrain bits 4..12 (the middle byte-straddling 8 bits).
        let bytes = s.check(16, &[Constraint::Eq(ext(4, 8), 0xBC)]).unwrap();
        let val = (u16::from_be_bytes([bytes[0], bytes[1]]) >> 4) & 0xFF;
        assert_eq!(val, 0xBC);
    }

    #[test]
    fn arithmetic_matches_interp_wrapping() {
        let mut s = Z3Solver::new();
        // ihl-style: ext(0,4)*4 - 20 == 4  =>  ext = 6
        let term = Term::Bin(
            BinOpKind::Sub,
            Box::new(Term::Bin(
                BinOpKind::Mul,
                Box::new(ext(0, 4)),
                Box::new(Term::Const(4)),
            )),
            Box::new(Term::Const(20)),
        );
        let bytes = s.check(8, &[Constraint::Eq(term, 4)]).unwrap();
        assert_eq!(bytes[0] >> 4, 6);
    }

    #[test]
    fn all_values_enumerates_nibble() {
        let mut s = Z3Solver::new();
        let vals = s.all_values(8, &[], &ext(0, 4), 32).unwrap();
        assert_eq!(vals, (0..16).collect::<Vec<u64>>());
        assert!(s.all_values(8, &[], &ext(0, 8), 16).is_err());
    }

    #[test]
    fn min_max_bounds_and_unsat() {
        let mut s = Z3Solver::new();
        // Nibble constrained to [3, 9] -> min 3, max 9.
        let mm = s
            .min_max(8, &[Constraint::InRange(ext(0, 4), 3, 9)], &ext(0, 4))
            .unwrap();
        assert_eq!(mm, Some((3, 9)));
        // Unconstrained nibble -> full [0, 15].
        let full = s.min_max(8, &[], &ext(0, 4)).unwrap();
        assert_eq!(full, Some((0, 15)));
        // Contradiction -> None.
        let unsat = s
            .min_max(
                8,
                &[
                    Constraint::Eq(ext(0, 4), 1),
                    Constraint::Not(Box::new(Constraint::Eq(ext(0, 4), 1))),
                ],
                &ext(0, 4),
            )
            .unwrap();
        assert_eq!(unsat, None);
    }

    #[test]
    fn masked_and_range_semantics() {
        let mut s = Z3Solver::new();
        let m = s
            .check(8, &[Constraint::Masked(ext(0, 8), 0xA0, 0xF0)])
            .unwrap();
        assert_eq!(m[0] & 0xF0, 0xA0);
        let r = s.check(8, &[Constraint::InRange(ext(0, 8), 5, 7)]).unwrap();
        assert!((5..=7).contains(&r[0]));
    }
}
