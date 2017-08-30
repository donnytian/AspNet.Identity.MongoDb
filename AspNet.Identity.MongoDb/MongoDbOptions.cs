using Microsoft.AspNetCore.Identity;

namespace AspNet.Identity.MongoDb
{
    /// <summary>
    /// Represents all the options you can use to configure the MongoDB stores for Identity Framework.
    /// </summary>
    public class MongoDbOptions
    {
        /// <summary>
        /// Gets or sets the connection string for MongoDB.
        /// </summary>
        public string ConnectionString { get; set; }

        /// <summary>
        /// Gets or sets the collection name for users.
        /// </summary>
        public string UserCollectionName { get; set; }

        /// <summary>
        /// Gets or sets the collection name for roles.
        /// </summary>
        public string RoleCollectionName { get; set; }

        /// <summary>
        /// Gets or set the error decriber.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }
    }
}
