#include "myrbtree.h"

void myrb_left_rotate(myrb_tree *T, struct myrb_node *node)
{
    struct myrb_node *x = node;
    struct myrb_node *y = node->rc;

    x->rc = y->lc;
    if (y->lc)
        y->lc->par = x;

    y->par = x->par;
    /*if x is the root then set the root as y*/
    if (x->par == NULL)
        (*T) = y;
    else if (x == x->par->lc) /* x is the lc of its parent*/
        x->par->lc = y;
    else if (x == x->par->rc) /* x is the rc of its parent*/
        x->par->rc = y;

    y->lc = x;
    x->par = y;

    return;
}

void myrb_right_rotate(myrb_tree *T, struct myrb_node *node)
{
    struct myrb_node *x = node;
    struct myrb_node *y = node->lc;

    x->lc = y->rc;
    if (y->rc)
        y->rc->par = x;

    y->par = x->par;
    if (x->par == NULL)
        (*T) = x;
    else if (x == x->par->lc)
        x->par->lc = y;
    else if (x == x->par->rc)
        x->par->rc = y;

    y->rc = x;
    x->par = y;

    return;
}

void myrb_insert(myrb_tree *T, KElemType key)
{
}

void myrb_node_insert(myrb_tree *T, struct myrb_node *node)
{
    // case 1: node is root
    // if the rb tree is empty, then let this node to be the root node
    if ((*T) == NULL)
    {
        node->col = BLACK;
        (*T) = node;
        return;
    }

    // find the pos of this node in the tree
    struct myrb_node *p, *par;
    p = T;
    par = NULL;
    while (p != NULL)
    {
        par = p;
        if (p->key > node->key)
        {
            p = p->rc;
        }
        else if (p->key < node->key)
        {
            p = p->lc;
        }
        else // p->key==node->key,indicate the node has existed
        {
            return;
        }
    }
    // insert node into the tree
    node->par = par;
    if (node->key < p->key) //node is the lc of par
        par->lc = node;
    else //node is the rc if par
        par->rc = node;

    node->col = RED; //let node be red

    // case 2: par of node is black
    if (par->col == BLACK)
        return; //T has been a rb tree

    // case 3: par of node is red
    myrb_node_insert_fix_up(T, node);
}

void myrb_node_insert_fix_up(myrb_tree *T, struct myrb_node *node)
{
    struct myrb_node *par = node->par;
    // case 1
    if (par == NULL)
        node->col = BLACK;
    return;

    // case 2:
    if (par->col == BLACK)
        return;

    // case 3:
    struct myrb_node *gp, *uncle;
    gp = par->par;
    if (par == gp->lc)
        uncle = gp->rc;
    else
        uncle = gp->lc;
    // case 3.1
    // par node and uncle node are both red
    if (uncle && uncle->col == RED)
    {
        uncle->col = BLACK;
        par->col = BLACK;
        gp->col = RED;
        myrb_node_insert_fix_up(T, gp);
        return;
    }

    // case 3.2
    if((!uncle||uncle->col==BLACK)&&(gp->lc==par))
    {
        return ;
    }

    //case 3.3
    if ((!uncle || uncle->col == BLACK) && (gp->rc == par))
    {
        return;
    }
}

void myrb_node_delete(myrb_tree T)
{
    printf("this function myrb_node_delete!\n");
}
