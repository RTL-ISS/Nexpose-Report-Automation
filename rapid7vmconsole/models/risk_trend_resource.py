# coding: utf-8

"""
    Python InsightVM API Client

    OpenAPI spec version: 3
    Contact: support@rapid7.com
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class RiskTrendResource(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'all_assets': 'RiskTrendAllAssetsResource',
        'asset_group_membership': 'str',
        'asset_groups': 'str',
        'assets': 'bool',
        '_from': 'str',
        'sites': 'str',
        'tag_membership': 'str',
        'tags': 'str',
        'to': 'str'
    }

    attribute_map = {
        'all_assets': 'allAssets',
        'asset_group_membership': 'assetGroupMembership',
        'asset_groups': 'assetGroups',
        'assets': 'assets',
        '_from': 'from',
        'sites': 'sites',
        'tag_membership': 'tagMembership',
        'tags': 'tags',
        'to': 'to'
    }

    def __init__(self, all_assets=None, asset_group_membership=None, asset_groups=None, assets=None, _from=None, sites=None, tag_membership=None, tags=None, to=None):  # noqa: E501
        """RiskTrendResource - a model defined in Swagger"""  # noqa: E501

        self._all_assets = None
        self._asset_group_membership = None
        self._asset_groups = None
        self._assets = None
        self.__from = None
        self._sites = None
        self._tag_membership = None
        self._tags = None
        self._to = None
        self.discriminator = None

        if all_assets is not None:
            self.all_assets = all_assets
        if asset_group_membership is not None:
            self.asset_group_membership = asset_group_membership
        if asset_groups is not None:
            self.asset_groups = asset_groups
        if assets is not None:
            self.assets = assets
        if _from is not None:
            self._from = _from
        if sites is not None:
            self.sites = sites
        if tag_membership is not None:
            self.tag_membership = tag_membership
        if tags is not None:
            self.tags = tags
        if to is not None:
            self.to = to

    @property
    def all_assets(self):
        """Gets the all_assets of this RiskTrendResource.  # noqa: E501

        Trend settings for a trend across all assets in the scope of the report.  # noqa: E501

        :return: The all_assets of this RiskTrendResource.  # noqa: E501
        :rtype: RiskTrendAllAssetsResource
        """
        return self._all_assets

    @all_assets.setter
    def all_assets(self, all_assets):
        """Sets the all_assets of this RiskTrendResource.

        Trend settings for a trend across all assets in the scope of the report.  # noqa: E501

        :param all_assets: The all_assets of this RiskTrendResource.  # noqa: E501
        :type: RiskTrendAllAssetsResource
        """

        self._all_assets = all_assets

    @property
    def asset_group_membership(self):
        """Gets the asset_group_membership of this RiskTrendResource.  # noqa: E501

        Whether all asset groups in the history of deployment or those as of the report generation time are to be included.  # noqa: E501

        :return: The asset_group_membership of this RiskTrendResource.  # noqa: E501
        :rtype: str
        """
        return self._asset_group_membership

    @asset_group_membership.setter
    def asset_group_membership(self, asset_group_membership):
        """Sets the asset_group_membership of this RiskTrendResource.

        Whether all asset groups in the history of deployment or those as of the report generation time are to be included.  # noqa: E501

        :param asset_group_membership: The asset_group_membership of this RiskTrendResource.  # noqa: E501
        :type: str
        """
        allowed_values = ["historical", "generation"]  # noqa: E501
        if asset_group_membership not in allowed_values:
            raise ValueError(
                "Invalid value for `asset_group_membership` ({0}), must be one of {1}"  # noqa: E501
                .format(asset_group_membership, allowed_values)
            )

        self._asset_group_membership = asset_group_membership

    @property
    def asset_groups(self):
        """Gets the asset_groups of this RiskTrendResource.  # noqa: E501

        Whether to include a trend for the 5 highest-risk asset groups in the scope of the report (either the average or total risk). Only allowed if asset groups are specified in the report scope.  # noqa: E501

        :return: The asset_groups of this RiskTrendResource.  # noqa: E501
        :rtype: str
        """
        return self._asset_groups

    @asset_groups.setter
    def asset_groups(self, asset_groups):
        """Sets the asset_groups of this RiskTrendResource.

        Whether to include a trend for the 5 highest-risk asset groups in the scope of the report (either the average or total risk). Only allowed if asset groups are specified in the report scope.  # noqa: E501

        :param asset_groups: The asset_groups of this RiskTrendResource.  # noqa: E501
        :type: str
        """
        allowed_values = ["average", "total"]  # noqa: E501
        if asset_groups not in allowed_values:
            raise ValueError(
                "Invalid value for `asset_groups` ({0}), must be one of {1}"  # noqa: E501
                .format(asset_groups, allowed_values)
            )

        self._asset_groups = asset_groups

    @property
    def assets(self):
        """Gets the assets of this RiskTrendResource.  # noqa: E501

        Whether to include a trend for the 5 highest-risk assets in the scope of the report.  # noqa: E501

        :return: The assets of this RiskTrendResource.  # noqa: E501
        :rtype: bool
        """
        return self._assets

    @assets.setter
    def assets(self, assets):
        """Sets the assets of this RiskTrendResource.

        Whether to include a trend for the 5 highest-risk assets in the scope of the report.  # noqa: E501

        :param assets: The assets of this RiskTrendResource.  # noqa: E501
        :type: bool
        """

        self._assets = assets

    @property
    def _from(self):
        """Gets the _from of this RiskTrendResource.  # noqa: E501

        The start date of the risk trend, which can either be a duration or a specific date and time.  # noqa: E501

        :return: The _from of this RiskTrendResource.  # noqa: E501
        :rtype: str
        """
        return self.__from

    @_from.setter
    def _from(self, _from):
        """Sets the _from of this RiskTrendResource.

        The start date of the risk trend, which can either be a duration or a specific date and time.  # noqa: E501

        :param _from: The _from of this RiskTrendResource.  # noqa: E501
        :type: str
        """
        allowed_values = ["P1Y", "P6M", "P3M", "P1M", "<date>"]  # noqa: E501
        if _from not in allowed_values:
            raise ValueError(
                "Invalid value for `_from` ({0}), must be one of {1}"  # noqa: E501
                .format(_from, allowed_values)
            )

        self.__from = _from

    @property
    def sites(self):
        """Gets the sites of this RiskTrendResource.  # noqa: E501

        Whether to include a trend for the 5 highest-risk sites in the scope of the report (either the average or total risk). Only allowed if sites are specified in the report scope.  # noqa: E501

        :return: The sites of this RiskTrendResource.  # noqa: E501
        :rtype: str
        """
        return self._sites

    @sites.setter
    def sites(self, sites):
        """Sets the sites of this RiskTrendResource.

        Whether to include a trend for the 5 highest-risk sites in the scope of the report (either the average or total risk). Only allowed if sites are specified in the report scope.  # noqa: E501

        :param sites: The sites of this RiskTrendResource.  # noqa: E501
        :type: str
        """
        allowed_values = ["average", "total"]  # noqa: E501
        if sites not in allowed_values:
            raise ValueError(
                "Invalid value for `sites` ({0}), must be one of {1}"  # noqa: E501
                .format(sites, allowed_values)
            )

        self._sites = sites

    @property
    def tag_membership(self):
        """Gets the tag_membership of this RiskTrendResource.  # noqa: E501

        Whether all assets tagged in the history of deployment or those tagged as of the report generation time are to be included.  # noqa: E501

        :return: The tag_membership of this RiskTrendResource.  # noqa: E501
        :rtype: str
        """
        return self._tag_membership

    @tag_membership.setter
    def tag_membership(self, tag_membership):
        """Sets the tag_membership of this RiskTrendResource.

        Whether all assets tagged in the history of deployment or those tagged as of the report generation time are to be included.  # noqa: E501

        :param tag_membership: The tag_membership of this RiskTrendResource.  # noqa: E501
        :type: str
        """
        allowed_values = ["historical", "generation"]  # noqa: E501
        if tag_membership not in allowed_values:
            raise ValueError(
                "Invalid value for `tag_membership` ({0}), must be one of {1}"  # noqa: E501
                .format(tag_membership, allowed_values)
            )

        self._tag_membership = tag_membership

    @property
    def tags(self):
        """Gets the tags of this RiskTrendResource.  # noqa: E501

        Whether to include a trend for the 5 highest-risk tags for assets in the scope of the report (either the average or total risk). Only allowed if tags are specified in the report scope.  # noqa: E501

        :return: The tags of this RiskTrendResource.  # noqa: E501
        :rtype: str
        """
        return self._tags

    @tags.setter
    def tags(self, tags):
        """Sets the tags of this RiskTrendResource.

        Whether to include a trend for the 5 highest-risk tags for assets in the scope of the report (either the average or total risk). Only allowed if tags are specified in the report scope.  # noqa: E501

        :param tags: The tags of this RiskTrendResource.  # noqa: E501
        :type: str
        """
        allowed_values = ["average", "total"]  # noqa: E501
        if tags not in allowed_values:
            raise ValueError(
                "Invalid value for `tags` ({0}), must be one of {1}"  # noqa: E501
                .format(tags, allowed_values)
            )

        self._tags = tags

    @property
    def to(self):
        """Gets the to of this RiskTrendResource.  # noqa: E501

        The end date of the risk trend (empty if `from` is a duration).  # noqa: E501

        :return: The to of this RiskTrendResource.  # noqa: E501
        :rtype: str
        """
        return self._to

    @to.setter
    def to(self, to):
        """Sets the to of this RiskTrendResource.

        The end date of the risk trend (empty if `from` is a duration).  # noqa: E501

        :param to: The to of this RiskTrendResource.  # noqa: E501
        :type: str
        """

        self._to = to

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(RiskTrendResource, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, RiskTrendResource):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
