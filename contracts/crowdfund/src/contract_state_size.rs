//! # contract_state_size
//!
//! @title   ContractStateSize — Centralized limits for variable-size contract state
//! @notice  Bounds metadata strings and collection growth so the crowdfund
//!          contract cannot accumulate unreviewed, unbounded state over time.
//! @dev     The helpers in this module are pure and return `Result<(), &'static str>`
//!          so they can be reused from contract logic, tests, and off-chain
//!          tooling without coupling to `ContractError`.
//!
//! ## Why these limits exist
//!
//! The crowdfund contract stores several fields whose size is controlled by
//! user input:
//!
//! 1. Metadata strings (`title`, `description`, `socials`, bonus-goal text)
//! 2. Contributor and pledger address lists
//! 3. Roadmap item descriptions
//! 4. Stretch-goal vectors
//!
//! Without explicit bounds, these values can grow until:
//!
//! - CI tests become slower and more memory-intensive
//! - Storage growth becomes harder to reason about during review
//! - Contract calls that iterate over vectors become less predictable
//! - Off-chain tooling sees inconsistent or excessively large payloads
//!
//! ## Security assumptions
//!
//! 1. Fixed maxima make worst-case state growth auditable.
//! 2. Rejecting oversize writes before persistence prevents silent storage bloat.
//! 3. Bounding collection counts reduces gas and event-surface risk in flows
//!    that later read or iterate over those collections.
//! 4. Metadata limits are sized for practical UX while preventing abuse via
//!    arbitrarily large strings.

use soroban_sdk::String;

/// Maximum number of contributor addresses stored in the contributor index.
///
/// @dev Contributions themselves remain stored per-address. This limit bounds
///      the enumerated contributor list used by view methods and reward flows.
pub const MAX_CONTRIBUTORS: u32 = 128;

/// Maximum number of pledger addresses stored in the pledger index.
pub const MAX_PLEDGERS: u32 = 128;

/// Maximum number of roadmap items allowed for a campaign.
pub const MAX_ROADMAP_ITEMS: u32 = 32;

/// Maximum number of stretch-goal milestones allowed for a campaign.
pub const MAX_STRETCH_GOALS: u32 = 32;

/// Maximum UTF-8 byte length for the campaign title.
pub const MAX_TITLE_LENGTH: u32 = 128;

/// Maximum UTF-8 byte length for the campaign description.
pub const MAX_DESCRIPTION_LENGTH: u32 = 2_048;

/// Maximum UTF-8 byte length for the social-links field.
pub const MAX_SOCIAL_LINKS_LENGTH: u32 = 512;

/// Maximum UTF-8 byte length for the optional bonus-goal description.
pub const MAX_BONUS_GOAL_DESCRIPTION_LENGTH: u32 = 280;

/// Maximum UTF-8 byte length for a roadmap item description.
pub const MAX_ROADMAP_DESCRIPTION_LENGTH: u32 = 280;

/// Maximum combined metadata footprint for title + description + socials.
///
/// @dev This budget is intentionally stricter than the sum of the individual
///      field maxima so callers cannot max out every metadata field at once.
pub const MAX_METADATA_TOTAL_LENGTH: u32 = 2_304;

#[inline]
fn validate_string_length(
    value: &String,
    max_length: u32,
    error: &'static str,
) -> Result<(), &'static str> {
    if value.len() > max_length {
        return Err(error);
    }
    Ok(())
}

#[inline]
fn validate_next_count(
    current_count: u32,
    max_count: u32,
    error: &'static str,
) -> Result<(), &'static str> {
    if current_count >= max_count {
        return Err(error);
    }
    Ok(())
}

/// Validates the campaign title length.
///
/// @param title Proposed title string.
/// @return `Ok(())` when `title.len() <= MAX_TITLE_LENGTH`.
pub fn validate_title(title: &String) -> Result<(), &'static str> {
    validate_string_length(
        title,
        MAX_TITLE_LENGTH,
        "title exceeds MAX_TITLE_LENGTH bytes",
    )
}

/// Validates the campaign description length.
///
/// @param description Proposed description string.
/// @return `Ok(())` when `description.len() <= MAX_DESCRIPTION_LENGTH`.
pub fn validate_description(description: &String) -> Result<(), &'static str> {
    validate_string_length(
        description,
        MAX_DESCRIPTION_LENGTH,
        "description exceeds MAX_DESCRIPTION_LENGTH bytes",
    )
}

/// Validates the social-links field length.
///
/// @param socials Proposed social-links string.
/// @return `Ok(())` when `socials.len() <= MAX_SOCIAL_LINKS_LENGTH`.
pub fn validate_social_links(socials: &String) -> Result<(), &'static str> {
    validate_string_length(
        socials,
        MAX_SOCIAL_LINKS_LENGTH,
        "social links exceed MAX_SOCIAL_LINKS_LENGTH bytes",
    )
}

/// Validates the optional bonus-goal description length.
///
/// @param description Proposed bonus-goal description.
/// @return `Ok(())` when the value fits within the configured bound.
pub fn validate_bonus_goal_description(description: &String) -> Result<(), &'static str> {
    validate_string_length(
        description,
        MAX_BONUS_GOAL_DESCRIPTION_LENGTH,
        "bonus goal description exceeds MAX_BONUS_GOAL_DESCRIPTION_LENGTH bytes",
    )
}

/// Validates a roadmap item description length.
///
/// @param description Proposed roadmap text.
/// @return `Ok(())` when the roadmap text is within the configured limit.
pub fn validate_roadmap_description(description: &String) -> Result<(), &'static str> {
    validate_string_length(
        description,
        MAX_ROADMAP_DESCRIPTION_LENGTH,
        "roadmap description exceeds MAX_ROADMAP_DESCRIPTION_LENGTH bytes",
    )
}

/// Validates the combined metadata footprint.
///
/// @param title_length Campaign title length in bytes.
/// @param description_length Campaign description length in bytes.
/// @param socials_length Social-links field length in bytes.
/// @return `Ok(())` when the total fits within `MAX_METADATA_TOTAL_LENGTH`.
pub fn validate_metadata_total_length(
    title_length: u32,
    description_length: u32,
    socials_length: u32,
) -> Result<(), &'static str> {
    let total = title_length
        .checked_add(description_length)
        .and_then(|value| value.checked_add(socials_length))
        .unwrap_or(u32::MAX);

    if total > MAX_METADATA_TOTAL_LENGTH {
        return Err("metadata exceeds MAX_METADATA_TOTAL_LENGTH bytes");
    }

    Ok(())
}

/// Validates that a new contributor can be added to the indexed contributor list.
///
/// @param current_count Current number of indexed contributors.
/// @return `Ok(())` when `current_count < MAX_CONTRIBUTORS`.
pub fn validate_contributor_capacity(current_count: u32) -> Result<(), &'static str> {
    validate_next_count(
        current_count,
        MAX_CONTRIBUTORS,
        "contributors exceed MAX_CONTRIBUTORS",
    )
}

/// Validates that a new pledger can be added to the indexed pledger list.
///
/// @param current_count Current number of indexed pledgers.
/// @return `Ok(())` when `current_count < MAX_PLEDGERS`.
pub fn validate_pledger_capacity(current_count: u32) -> Result<(), &'static str> {
    validate_next_count(current_count, MAX_PLEDGERS, "pledgers exceed MAX_PLEDGERS")
}

/// Validates that a new roadmap item can be appended.
///
/// @param current_count Current number of roadmap items.
/// @return `Ok(())` when `current_count < MAX_ROADMAP_ITEMS`.
pub fn validate_roadmap_capacity(current_count: u32) -> Result<(), &'static str> {
    validate_next_count(
        current_count,
        MAX_ROADMAP_ITEMS,
        "roadmap exceeds MAX_ROADMAP_ITEMS",
    )
}

/// Validates that a new stretch goal can be appended.
///
/// @param current_count Current number of stretch goals.
/// @return `Ok(())` when `current_count < MAX_STRETCH_GOALS`.
pub fn validate_stretch_goal_capacity(current_count: u32) -> Result<(), &'static str> {
    validate_next_count(
        current_count,
        MAX_STRETCH_GOALS,
        "stretch goals exceed MAX_STRETCH_GOALS",
    )
}
