using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;

using PixivCS.Utils;

namespace PixivCS
{
    public class PixivAppAPI : PixivBaseAPI
    {
        public PixivAppAPI(string AccessToken, string RefreshToken, string UserID,ClientOutput ClientLog, bool ExperimentalConnection = false) :
            base(AccessToken, RefreshToken, UserID, ClientLog, ExperimentalConnection)
        { }

        public PixivAppAPI() : base() { }

        public PixivAppAPI(PixivBaseAPI BaseAPI) : base(BaseAPI) { }

        public async Task<HttpResponseMessage> RequestCall(string Method, string Url,
            Dictionary<string, string> Headers = null, List<(string, string)> Query = null,
            HttpContent Body = null, bool RequireAuth = true)
        {
            var headers = Headers ?? new Dictionary<string, string>();
            if (!(headers.ContainsKey("User-Agent") || headers.ContainsKey("user-agent")))
            {
                headers.Add("App-OS", "Android");
                headers.Add("App-OS-Version", "Android 6.0");
                headers.Add("App-Version", "5.0.166");
                headers.Add("User-Agent", "PixivAndroidApp/5.0.155 (Android 6.0; Pixel C)");
            }
            if (RequireAuth) headers.Add("Authorization", string.Format("Bearer {0}", AccessToken));
            return await base.RequestCall(Method, Url, headers, Query, Body);
        }

        /// <summary>
        /// 用户详情
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Filter"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserDetail> GetUserDetailAsync(string UserID, string Filter = "for_android",
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/detail";
            List<(string, string)> query = new List<(string, string)>
            {
                ("user_id", UserID),
                ("filter", Filter)
            };
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserDetail>();
        }

        /// <summary>
        /// 用户作品
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="IllustType"></param>
        /// <param name="Filter"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserIllusts> GetUserIllustsAsync(string UserID, string IllustType = "illust",
            string Filter = "for_ios", string Offset = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/illusts";
            List<(string, string)> query = new List<(string, string)>
            {
                ("user_id", UserID),
                ("filter", Filter)
            };
            if (!string.IsNullOrEmpty(IllustType)) query.Add(("type", IllustType));
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserIllusts>();
        }

        /// <summary>
        /// 用户收藏
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Restrict"></param>
        /// <param name="Filter"></param>
        /// <param name="MaxBookmarkID"></param>
        /// <param name="Tag"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserIllusts> GetUserBookmarksIllustAsync(string UserID, string Restrict = "public",
            string Filter = "for_ios", string MaxBookmarkID = null, string Tag = null,
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/bookmarks/illust";
            List<(string, string)> query = new List<(string, string)>
            {
                ("user_id", UserID),
                ("restrict", Restrict),
                ("filter", Filter)
            };
            if (!string.IsNullOrEmpty(MaxBookmarkID)) query.Add(("max_bookmark_id", MaxBookmarkID));
            if (!string.IsNullOrEmpty(Tag)) query.Add(("tag", Tag));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserIllusts>();
        }

        /// <summary>
        /// 关注者的新作品
        /// </summary>
        /// <param name="Restrict"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserIllusts> GetIllustFollowAsync(string Restrict = "public", string Offset = null,
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v2/illust/follow";
            List<(string, string)> query = new List<(string, string)>
            {
                ("restrict", Restrict)
            };
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserIllusts>();
        }

        /// <summary>
        /// 作品详情
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.IllustDetail> GetIllustDetailAsync(string IllustID, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/illust/detail";
            List<(string, string)> query = new List<(string, string)>
            {
                ("illust_id", IllustID)
            };
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.IllustDetail>();
        }

        /// <summary>
        /// 作品评论
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="Offset"></param>
        /// <param name="IncludeTotalComments">决定是否在返回的JSON中包含总评论数</param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.IllustComments> GetIllustCommentsAsync(string IllustID, string Offset = null,
            bool? IncludeTotalComments = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/illust/comments";
            List<(string, string)> query = new List<(string, string)>
            {
                ("illust_id", IllustID)
            };
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            if (IncludeTotalComments != null) query.Add(("include_total_comments",
                IncludeTotalComments.Value ? "true" : "false"));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.IllustComments>();
        }

        /// <summary>
        /// 发表评论
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="Comment"></param>
        /// <param name="ParentCommentID"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.IllustCommentAddResult> PostIllustCommentAddAsync(string IllustID, string Comment,
            string ParentCommentID = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/illust/comment/add";
            Dictionary<string, string> data = new Dictionary<string, string>
            {
                { "illust_id", IllustID },
                { "comment", Comment }
            };
            if (!string.IsNullOrWhiteSpace(ParentCommentID))
                data.Add("parent_comment_id", ParentCommentID);
            var res = await RequestCall("POST", url, Body: new FormUrlEncodedContent(data),
                RequireAuth: RequireAuth);
            return await res.GetResult<Objects.IllustCommentAddResult>();
        }

        /// <summary>
        /// 相关作品
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="Filter"></param>
        /// <param name="SeedIllustIDs"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserIllusts> GetIllustRelatedAsync(string IllustID, string Filter = "for_android",
            List<string> SeedIllustIDs = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v2/illust/related";
            List<(string, string)> query = new List<(string, string)>
            {
                ("illust_id", IllustID),
                ("filter", Filter)
            };
            if (SeedIllustIDs != null)
            {
                foreach (var i in SeedIllustIDs)
                    query.Add(("seed_illust_ids[]", i));
            }
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserIllusts>();
        }

        /// <summary>
        /// 首页推荐
        /// </summary>
        /// <param name="ContentType">content_type: [illust, manga]</param>
        /// <param name="IncludeRankingLabel"></param>
        /// <param name="Filter"></param>
        /// <param name="MaxBookmarkIDForRecommended"></param>
        /// <param name="MinBookmarkIDForRecentIllust"></param>
        /// <param name="Offset"></param>
        /// <param name="IncludeRankingIllusts"></param>
        /// <param name="BookmarkIllustIDs"></param>
        /// <param name="IncludePrivacyPolicy"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.IllustRecommended> GetIllustRecommendedAsync(string ContentType = "illust",
            bool IncludeRankingLabel = true, string Filter = "for_ios",
            string MaxBookmarkIDForRecommended = null,
            string MinBookmarkIDForRecentIllust = null, string Offset = null,
            bool? IncludeRankingIllusts = null, List<string> BookmarkIllustIDs = null,
            string IncludePrivacyPolicy = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = RequireAuth ? "https://app-api.pixiv.net/v1/illust/recommended" :
                "https://app-api.pixiv.net/v1/illust/recommended-nologin";
            List<(string, string)> query = new List<(string, string)>
            {
                ("content_type", ContentType),
                ("include_ranking_label", IncludeRankingLabel ? "true" : "false"),
                ("filter", Filter)
            };
            if (!string.IsNullOrEmpty(MaxBookmarkIDForRecommended))
                query.Add(("max_bookmark_id_for_recommend", MaxBookmarkIDForRecommended));
            if (!string.IsNullOrEmpty(MinBookmarkIDForRecentIllust))
                query.Add(("min_bookmark_id_for_recent_illust", MinBookmarkIDForRecentIllust));
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            if (IncludeRankingIllusts != null)
                query.Add(("include_ranking_illusts", IncludeRankingIllusts.Value ? "true" : "false"));
            string ids = "";
            if (BookmarkIllustIDs != null)
                foreach (var i in BookmarkIllustIDs)
                    ids += (i + ",");
            if (ids != "")
            {
                ids.TrimEnd(',');
                query.Add(("bookmark_illust_ids", ids));
            }
            if (!string.IsNullOrEmpty(IncludePrivacyPolicy))
                query.Add(("include_privacy_policy", IncludePrivacyPolicy));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.IllustRecommended>();
        }

        /// <summary>
        /// 作品排行
        /// </summary>
        /// <param name="Mode">mode: [day, week, month, day_male, day_female, week_original, week_rookie, day_manga]</param>
        /// <param name="Filter"></param>
        /// <param name="Date">date: yyyy-mm-dd</param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserIllusts> GetIllustRankingAsync(string Mode = "day", string Filter = "for_android",
            string Date = null, string Offset = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/illust/ranking";
            List<(string, string)> query = new List<(string, string)>
            {
                ("mode", Mode),
                ("filter", Filter)
            };
            if (!string.IsNullOrEmpty(Date)) query.Add(("date", Date));
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserIllusts>();
        }

        //趋势标签
        public async Task<Objects.TrendingTagsIllust> GetTrendingTagsIllustAsync(string Filter = "for_android", bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/trending-tags/illust";
            List<(string, string)> query = new List<(string, string)>
            {
                ("filter", Filter)
            };
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.TrendingTagsIllust>();
        }

        /// <summary>
        /// 搜索
        /// </summary>
        /// <param name="Word"></param>
        /// <param name="SearchTarget">
        /// search_target - 搜索类型<br/>
        /// <c>partial_match_for_tags</c>  - 标签部分一致<br/>
        /// <c>exact_match_for_tags</c>    - 标签完全一致<br/>
        /// <c>title_and_caption</c>       - 标题说明文<br/>
        /// </param>
        /// <param name="Sort">sort: [date_desc, date_asc]</param>
        /// <param name="Duration">duration: [within_last_day, within_last_week, within_last_month]</param>
        /// <param name="Filter"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.SearchIllustResult> GetSearchIllustAsync(string Word, string SearchTarget = "partial_match_for_tags",
            string Sort = "date_desc", string Duration = null, string Filter = "for_ios", string Offset = null,
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/search/illust";
            List<(string, string)> query = new List<(string, string)>
            {
                ("word", Word),
                ("search_target", SearchTarget),
                ("sort", Sort),
                ("filter", Filter)
            };
            if (!string.IsNullOrEmpty(Duration)) query.Add(("duration", Duration));
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.SearchIllustResult>();
        }

        /// <summary>
        /// 作品收藏详情
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.IllustBookmarkDetail> GetIllustBookmarkDetailAsync(string IllustID, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v2/illust/bookmark/detail";
            List<(string, string)> query = new List<(string, string)>
            {
                ("illust_id", IllustID)
            };
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.IllustBookmarkDetail>();
        }

        /// <summary>
        /// 新增收藏
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="Restrict"></param>
        /// <param name="Tags"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task PostIllustBookmarkAddAsync(string IllustID, string Restrict = "public",
            List<string> Tags = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v2/illust/bookmark/add";
            Dictionary<string, string> data = new Dictionary<string, string>
            {
                { "illust_id", IllustID },
                { "restrict", Restrict }
            };
            string tags = "";
            if (Tags != null)
                foreach (var i in Tags)
                    tags += (i + " ");
            tags = tags.Trim();
            if (tags != "")
                data.Add("tags", HttpUtility.UrlEncode(tags));
            await RequestCall("POST", url, Body: new FormUrlEncodedContent(data),
                RequireAuth: RequireAuth);
        }

        /// <summary>
        /// 删除收藏
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task PostIllustBookmarkDeleteAsync(string IllustID, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/illust/bookmark/delete";
            Dictionary<string, string> data = new Dictionary<string, string>
            {
                { "illust_id", IllustID }
            };
            await RequestCall("POST", url, Body: new FormUrlEncodedContent(data),
                RequireAuth: RequireAuth);
        }

        /// <summary>
        /// 用户收藏标签列表
        /// </summary>
        /// <param name="Restrict"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserBookmarkTags> GetUserBookmarkTagsIllustAsync(string Restrict = "public", string Offset = null,
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/bookmark-tags/illust";
            List<(string, string)> query = new List<(string, string)>
            {
                ("restrict", Restrict)
            };
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserBookmarkTags>();
        }

        /// <summary>
        /// Following用户列表
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Restrict"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserFollowList> GetUserFollowingAsync(string UserID, string Restrict = "public",
            string Offset = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/following";
            List<(string, string)> query = new List<(string, string)>
            {
                ("user_id", UserID),
                ("restrict", Restrict)
            };
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserFollowList>();
        }

        /// <summary>
        /// Followers用户列表
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Restrict"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserFollowList> GetUserFollowerAsync(string UserID, string Restrict = "public",
            string Offset = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/follower";
            List<(string, string)> query = new List<(string, string)>
            {
                ("user_id", UserID),
                ("restrict", Restrict)
            };
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserFollowList>();
        }

        /// <summary>
        /// 关注用户
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Restrict"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task PostUserFollowAddAsync(string UserID, string Restrict = "public",
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/follow/add";
            Dictionary<string, string> data = new Dictionary<string, string>
            {
                { "user_id", UserID },
                { "restrict", Restrict }
            };
            await RequestCall("POST", url, Body: new FormUrlEncodedContent(data),
                RequireAuth: RequireAuth);
        }

        /// <summary>
        /// 取关用户
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Restrict"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task PostUserFollowDeleteAsync(string UserID, string Restrict = "public",
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/follow/delete";
            Dictionary<string, string> data = new Dictionary<string, string>
            {
                { "user_id", UserID },
                { "restrict", Restrict }
            };
            await RequestCall("POST", url, Body: new FormUrlEncodedContent(data),
                RequireAuth: RequireAuth);
        }

        /// <summary>
        /// 好P友
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserFollowList> GetUserMyPixivAsync(string UserID, string Offset = null,
            bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/user/mypixiv";
            List<(string, string)> query = new List<(string, string)>
            {
                ("user_id", UserID)
            };
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserFollowList>();
        }

        /// <summary>
        /// 黑名单用户
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Filter"></param>
        /// <param name="Offset"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UserList> GetUserListAsync(string UserID, string Filter = "for_android",
            string Offset = null, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v2/user/list";
            List<(string, string)> query = new List<(string, string)>
            {
                ("user_id", UserID),
                ("filter", Filter)
            };
            if (!string.IsNullOrEmpty(Offset)) query.Add(("offset", Offset));
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UserList>();
        }

        /// <summary>
        /// Ugoira信息
        /// </summary>
        /// <param name="IllustID"></param>
        /// <param name="RequireAuth"></param>
        /// <returns></returns>
        public async Task<Objects.UgoiraMetadata> GetUgoiraMetadataAsync(string IllustID, bool RequireAuth = true)
        {
            if ((DateTime.UtcNow - AccessTime).TotalSeconds >= ExpireTime && RequireAuth)
            {
                await AuthAsync(RefreshToken);
            }
            string url = "https://app-api.pixiv.net/v1/ugoira/metadata";
            List<(string, string)> query = new List<(string, string)>
            {
                ("illust_id", IllustID)
            };
            var res = await RequestCall("GET", url, Query: query, RequireAuth: RequireAuth);
            return await res.GetResult<Objects.UgoiraMetadata>();
        }

        /// <summary>
        /// 特辑详情
        /// </summary>
        /// <remarks>
        /// 伪装成Chrome
        /// </remarks>
        /// <param name="ShowcaseID"></param>
        /// <returns></returns>
        public async Task<Objects.ShowcaseArticle> GetShowcaseArticleAsync(string ShowcaseID)
        {
            string url = "https://www.pixiv.net/ajax/showcase/article";
            Dictionary<string, string> headers = new Dictionary<string, string>
            {
                { "User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36" },
                { "Referer", "https://www.pixiv.net" }
            };
            List<(string, string)> query = new List<(string, string)>()
            {
                ("article_id", ShowcaseID)
            };
            var res = await RequestCall("GET", url, headers, Query: query, RequireAuth: false);
            return await res.GetResult<Objects.ShowcaseArticle>();
        }
    }
}
