//! 干净流量 Bloom 前置（仅加速；Bloom 负向不影响安全路径）。

/// 简单位数组 Bloom（训练插入干净键；查询 maybe_contains）。
#[derive(Debug)]
pub struct ClearBloom {
    bits: Vec<u64>,
    k: u32,
    count: usize,
}

impl ClearBloom {
    pub fn new(bit_count: usize, k: u32) -> Self {
        let words = bit_count.max(1024).div_ceil(64);
        Self {
            bits: vec![0; words],
            k: k.clamp(2, 8),
            count: 0,
        }
    }

    pub fn insert(&mut self, key: u64) {
        for i in 0..self.k {
            let idx = self.index(key, i);
            self.bits[idx] |= 1 << (key.wrapping_add(i as u64) % 64);
        }
        self.count += 1;
    }

    pub fn maybe_contains(&self, key: u64) -> bool {
        if self.count == 0 {
            return false;
        }
        (0..self.k).all(|i| {
            let idx = self.index(key, i);
            (self.bits[idx] & (1 << (key.wrapping_add(i as u64) % 64))) != 0
        })
    }

    fn index(&self, key: u64, roued: u32) -> usize {
        let mixed = key
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(roued as u64);
        (mixed as usize) % self.bits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_maybe() {
        let mut b = ClearBloom::new(4096, 4);
        b.insert(42);
        assert!(b.maybe_contains(42));
        assert!(!b.maybe_contains(99));
    }
}
