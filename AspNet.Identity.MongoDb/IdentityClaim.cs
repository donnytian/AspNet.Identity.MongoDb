using System.Security.Claims;

namespace AspNet.Identity.MongoDb
{
    /// <summary>Represents a claim that a user or role possesses.</summary>
    public class IdentityClaim
    {
        /// <summary>Gets or sets the claim type for this claim.</summary>
        public virtual string ClaimType { get; set; }

        /// <summary>Gets or sets the claim value for this claim.</summary>
        public virtual string ClaimValue { get; set; }

        /// <summary>Converts the entity into a Claim instance.</summary>
        /// <returns>Claim object.</returns>
        public virtual Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
        }

        /// <summary>Reads the type and value from the Claim.</summary>
        /// <param name="claim">The claim object.</param>
        public virtual void InitializeFromClaim(Claim claim)
        {
            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }

        /// <summary>
        /// Checks whether equals with another IdentityClaim.
        /// </summary>
        /// <param name="other">The object to check.</param>
        /// <returns>True if equals; otherwise false.</returns>
        public bool Equals(IdentityClaim other)
        {
            return other != null
                && other.ClaimType.Equals(ClaimType)
                && other.ClaimValue.Equals(ClaimValue);
        }

        /// <summary>
        /// Checks whether equals with another Claim.
        /// </summary>
        /// <param name="other">The claim object to check.</param>
        /// <returns>True if equals; otherwise false.</returns>
        public bool Equals(Claim other)
        {
            return other != null
                && other.Type.Equals(ClaimType)
                && other.Value.Equals(ClaimValue);
        }
    }
}
