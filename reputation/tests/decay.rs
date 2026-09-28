use delego_reputation::calculate_decayed_score;

#[test]
fn score_halves_at_each_half_life_and_converges_to_zero() {
    assert_eq!(calculate_decayed_score(10_000, 0, 10), 10_000);
    assert_eq!(calculate_decayed_score(10_000, 10, 10), 5_000);
    assert_eq!(calculate_decayed_score(10_000, 20, 10), 2_500);
    assert_eq!(calculate_decayed_score(10_000, 320, 10), 0);

    let mut previous = 10_000;
    for elapsed in 1..=320 {
        let score = calculate_decayed_score(10_000, elapsed, 10);
        assert!(score <= previous, "score increased at ledger {elapsed}");
        previous = score;
    }
}

#[test]
fn zero_half_life_preserves_the_historical_score() {
    assert_eq!(calculate_decayed_score(u32::MAX, 100, 0), u32::MAX);
}
